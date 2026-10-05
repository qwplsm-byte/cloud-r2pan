/**
 * WebDAV 协议实现 —— 挂载点 /webdav/*
 *
 * 支持的方法：
 *   OPTIONS   —— 探测 DAV 能力
 *   PROPFIND  —— 列出目录 / 文件属性（Depth: 0/1/infinity）
 *   GET       —— 下载文件
 *   HEAD      —— 仅返回文件元数据
 *   PUT       —— 上传/覆盖文件
 *   DELETE    —— 删除文件或空目录（非空目录递归删除）
 *   MKCOL     —— 创建目录
 *   MOVE      —— 移动 / 重命名 文件或目录
 *   COPY      —— 复制文件或目录
 *
 * 认证：HTTP Basic Auth，用户名密码在管理后台设置（settings.webdav_username / webdav_password_hash）
 * 存储：复用 StorageProvider（R2 / S3），文件元数据存 D1 files 表，目录存 directories 表
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { sha256Hex, safeEqual } from "./crypto";
import { createStorageProvider, type StorageProvider } from "./storage";
import { randomId } from "./db";

/* ═══════════ 懒加载 StorageProvider ═══════════ */
let _storagePromise: Promise<StorageProvider> | null = null;
async function storage(env: Env): Promise<StorageProvider> {
  if (!_storagePromise) {
    _storagePromise = (async () => {
      const s = await getSettings(env);
      return createStorageProvider(env, s);
    })();
  }
  return _storagePromise;
}

/* ═══════════ 工具函数 ═══════════ */

/** 路径标准化：确保以 / 开头，不以 / 结尾（根目录除外）
 *  非法编码（裸 %）会抛 URIError、分段含 .. 或 \0 会抛 Error —— 调用方捕获后返回 400 */
function normPath(p: string): string {
  p = decodeURIComponent(p);
  p = p.replace(/\\/g, "/").replace(/\/+/g, "/");
  if (!p.startsWith("/")) p = "/" + p;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  // 拒绝 .. 与 null 字节：/share/../x 可绕过 root 的 startsWith 检查
  const segs = p.split("/").filter(Boolean);
  if (segs.some((s) => s === ".." || s.includes("\0"))) {
    throw new Error("invalid path segment");
  }
  return p;
}

/** 从 WebDAV URL 提取内部路径（去掉 /webdav 前缀） */
function extractInternalPath(urlPath: string): string {
  // /webdav         → /
  // /webdav/        → /
  // /webdav/foo.txt → /foo.txt
  // /webdav/dir/a.txt → /dir/a.txt
  const stripped = urlPath.replace(/^\/webdav/, "");
  return normPath(stripped || "/");
}

/**
 * 从完整 URL 构建 WebDAV href（用于 PROPFIND 响应）
 *
 * ── B5 修复 ── 原实现把路径原样拼进 href：文件名含空格 / `#` / `?` / 非 ASCII 时，
 * 客户端会把 `#` 当片段截断、把 `?` 当查询串，拿不到该资源。这里逐段做 URL 编码。
 * trailingSlash=false 供文件使用（RFC 4918：目录才带尾斜杠，文件不应带）。
 */
function buildHref(baseUrl: string, internalPath: string, trailingSlash = true): string {
  const u = new URL(baseUrl);
  const segs = (internalPath === "/" ? "" : internalPath).split("/").filter(Boolean);
  const encoded = segs.map((s) => encodeURIComponent(s)).join("/");
  const path = encoded ? `/${encoded}` : "";
  return `${u.origin}/webdav${path}${trailingSlash ? "/" : ""}`;
}

/** LIKE 通配符转义 —— 把 % _ \ 转义,配合 ESCAPE '\' 使用 */
function likeEscape(p: string): string {
  return p.replace(/[\\%_]/g, (c) => "\\" + c);
}

/** RFC 1123 日期格式 */
function rfc1123(date: Date): string {
  return date.toUTCString().replace(/GMT$/, "GMT");
}

/** 将毫秒时间戳转 RFC 1123 */
function tsToRfc1123(ts: number): string {
  return rfc1123(new Date(ts));
}

/* ═══════════ Basic Auth 认证 ═══════════ */

/** 解析 Basic Auth 头 → {username, password} 或 null */
function parseBasicAuth(authHeader: string | null): { username: string; password: string } | null {
  if (!authHeader || !authHeader.startsWith("Basic ")) return null;
  try {
    const decoded = atob(authHeader.slice(6));
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { username: decoded.slice(0, i), password: decoded.slice(i + 1) };
  } catch {
    return null;
  }
}

/** 验证 WebDAV Basic Auth */
async function checkWebDAVAuth(req: Request, env: Env): Promise<boolean> {
  const settings = await getSettings(env);
  if (!settings.webdavEnabled) return false;
  if (!settings.webdavPasswordHash) return false;

  const auth = parseBasicAuth(req.headers.get("authorization"));
  if (!auth) return false;
  // ── B3 修复：用户名同样用恒定时间比较 ──
  // 原来是 `!==`，会按首个不同字符的位置提前返回，泄露用户名的前缀匹配进度。
  // 密码早就是 safeEqual，这里补齐对称实现（新 safeEqual 对长度不同也安全）。
  if (!safeEqual(auth.username, settings.webdavUsername)) return false;

  // 密码校验：salt:sha256(salt:password)
  const stored = settings.webdavPasswordHash;
  const i = stored.indexOf(":");
  if (i < 0) return false;
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + auth.password);
  return safeEqual(want, got);
}

/* ═══════════ 数据库辅助查询 ═══════════ */

interface DBFile {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  path: string;
  uploaded_at: number;
}

/** 查找一个文件（精确 path + name） */
async function findFile(env: Env, dir: string, name: string): Promise<DBFile | null> {
  const path = dir === "/" ? `/${name}` : `${dir}/${name}`;
  return await env.db
    .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path = ?1 AND name = ?2")
    .bind(path, name)
    .first<DBFile>();
}

/** 查找目录是否存在（directories 表 或 有文件直接在其中） */
async function directoryExists(env: Env, path: string): Promise<boolean> {
  path = path === "/" ? "/" : path.replace(/\/$/, "");
  if (path === "/") return true; // 根目录永远存在
  // directories 表
  const dir: any = await env.db.prepare("SELECT 1 FROM directories WHERE path = ?1").bind(path).first();
  if (dir) return true;
  // 有文件直接在这个目录下（不是子目录）
  const child: any = await env.db
    .prepare("SELECT 1 FROM files WHERE path = ?1 LIMIT 1")
    .bind(path)
    .first();
  if (child) return true;
  // 有文件以这个目录开头（更深层）—— 也算存在
  const deeper: any = await env.db
    .prepare("SELECT 1 FROM files WHERE path LIKE ?1 ESCAPE '\\' LIMIT 1")
    .bind(likeEscape(path) + "/%")
    .first();
  return !!deeper;
}

/** 列出目录的直接子项（文件 + 子目录） */
async function listDirChildren(env: Env, path: string): Promise<{ files: DBFile[]; dirs: string[] }> {
  path = path === "/" ? "" : path; // 查询时根目录用 "" 前缀
  const nextSlash = path ? path + "/" : "/";

  // 1. 直接子文件：path = 父路径 + "/" + name（精确）
  const { results: files } = await env.db
    .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path LIKE ?1 ESCAPE '\\'")
    .bind(path === "" ? "/%" : likeEscape(path) + "/%")
    .all<DBFile>();

  // 过滤出直接子文件（不是子目录里的）
  const directFiles: DBFile[] = [];
  const subDirSet = new Set<string>();

  for (const f of files) {
    // f.path 类似 "/foo" 或 "/dir/file.txt"
    const relPath = f.path;
    if (path === "") {
      // 根目录下："/foo" → 直接子项；"/sub/foo" → 子目录项
      const parts = relPath.split("/").filter(Boolean);
      if (parts.length === 1) {
        directFiles.push(f);
      } else if (parts.length >= 2) {
        subDirSet.add("/" + parts[0]);
      }
    } else {
      // 子目录下：path="/dir"，f.path="/dir/sub" 或 "/dir/file.txt"
      const rest = relPath.slice(nextSlash.length); // 去掉 "/dir/" 前缀
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        // 直接子文件
        directFiles.push(f);
      } else {
        // 属于某个子目录
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  // 2. directories 表里显式创建的子目录
  const dirPrefix = path === "" ? "/" : nextSlash;
  const { results: explicitDirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ?1 ESCAPE '\\' AND path != ?2")
    .bind(likeEscape(dirPrefix) + "%", path === "" ? "/" : path)
    .all<{ path: string }>();

  for (const d of explicitDirs) {
    if (path === "") {
      // 只取第一段
      const parts = d.path.split("/").filter(Boolean);
      if (parts.length >= 1) subDirSet.add("/" + parts[0]);
    } else {
      const rest = d.path.slice(nextSlash.length);
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        subDirSet.add(d.path);
      } else {
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  return { files: directFiles, dirs: Array.from(subDirSet).sort() };
}

/* ═══════════ PROPFIND XML 生成 ═══════════ */

/**
 * XML 转义。
 *
 * ── B7 修复：先剔除 XML 1.0 非法控制字符 ──
 * 文件名里若含 0x00-0x08 这类控制字符（UI 可输入、URL 也能编码进来），拼进 207 响应后
 * 客户端会解析**整份**文档失败（不只是那一条）。这里按码点过滤，保留合法的
 * Tab(0x09) / LF(0x0A) / CR(0x0D)，其余 C0 控制字符全部剔除。
 */
function escapeXml(s: string): string {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) continue;
    out += ch;
  }
  return out
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function filePropstatAsFile(file: DBFile, href: string): string {
  const displayName = escapeXml(file.name);
  const mime = escapeXml(file.mime || "application/octet-stream");
  const lastModified = tsToRfc1123(file.uploaded_at);
  const creationDate = new Date(file.uploaded_at).toISOString();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype/>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontentlength>${file.size}</getcontentlength>
        <getcontenttype>${mime}</getcontenttype>
        <getetag>"${file.id}"</getetag>
        <getlastmodified>${lastModified}</getlastmodified>
        <creationdate>${creationDate}</creationdate>
        <displayname>${displayName}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 目录自身的 propstat */
function dirPropstat(path: string, baseUrl: string): string {
  const href = buildHref(baseUrl, path);
  const displayName = path === "/" ? "/" : path.split("/").filter(Boolean).pop() || "";
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype><collection/></resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontenttype>httpd/unix-directory</getcontenttype>
        <getlastmodified>${tsToRfc1123(Date.now())}</getlastmodified>
        <creationdate>${new Date().toISOString()}</creationdate>
        <displayname>${escapeXml(displayName)}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 生成 multistatus XML 响应 */
function multistatusXML(responses: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">${responses.join("")}
</D:multistatus>`;
}

/* ═══════════ WebDAV 主入口 ═══════════ */

export async function handleWebDAV(
  req: Request,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  // 解析失败（裸 % / .. / \0）→ 400，避免 decodeURIComponent 抛 URIError 变成全局 500
  let internalPath: string;
  try {
    internalPath = extractInternalPath(url.pathname);
  } catch {
    return new Response("Bad Request", { status: 400 });
  }

  // 1. OPTIONS —— 不强制认证（让客户端先探测能力）
  // ── B2 修复：功能关闭时不再暴露「本站有 WebDAV」这一事实 ──
  // 原来无论开关如何都返回 DAV 能力头，等于对扫描器自曝服务存在。
  if (method === "OPTIONS") {
    const probe = await getSettings(env);
    if (!probe.webdavEnabled || !probe.webdavPasswordHash) {
      return new Response("Not Found", { status: 404 });
    }
    return new Response("", {
      status: 200,
      headers: {
        "Allow": "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY",
        // ── B1 修复 ── 原来声明 "1, 2, 3"（class 2=锁、3=版本控制），但本实现
        // 根本没有 LOCK/UNLOCK，客户端按声明去加锁必然拿到 405，
        // Windows 映射驱动器等客户端会因此直接放弃写入。降为 "1" 如实声明。
        "DAV": "1",
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
      },
    });
  }

  // 2. 认证
  if (!(await checkWebDAVAuth(req, env))) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": `Basic realm="cloud-r2pan WebDAV"`,
        "Content-Type": "text/plain",
      },
    });
  }

  // 3. 检查根路径限制（settings.webdav_root_path）
  const settings = await getSettings(env);
  const root = settings.webdavRootPath && settings.webdavRootPath !== "/"
    ? settings.webdavRootPath.replace(/\/+$/, "")
    : "";
  if (root && !(internalPath === root || internalPath.startsWith(root + "/"))) {
    return new Response("Forbidden", { status: 403 });
  }

  // 3.1 MOVE/COPY —— Destination 必须同源且位于 /webdav 下，目标路径同样受 root 限制
  if (method === "MOVE" || method === "COPY") {
    const destHeader = req.headers.get("destination");
    if (destHeader) {
      try {
        const destUrl = new URL(destHeader);
        if (destUrl.origin !== url.origin ||
            !(destUrl.pathname === "/webdav" || destUrl.pathname.startsWith("/webdav/"))) {
          return new Response("Invalid Destination", { status: 502 });
        }
        const destPath = extractInternalPath(destUrl.pathname);
        if (root && !(destPath === root || destPath.startsWith(root + "/"))) {
          return new Response("Forbidden", { status: 403 });
        }
      } catch { /* 无法解析的 Destination 交由各方法返回 400 */ }
    }
  }

  // 4. 分发到各方法处理
  switch (method) {
    case "PROPFIND":
      return handlePropfind(req, env, url, internalPath);
    case "GET":
      return handleWebDavGet(req, env, internalPath, false);
    case "HEAD":
      return handleWebDavGet(req, env, internalPath, true);
    case "PUT":
      return handleWebDavPut(req, env, internalPath);
    case "DELETE":
      return handleWebDavDelete(env, internalPath);
    case "MKCOL":
      return handleWebDavMkcol(env, internalPath);
    case "MOVE":
      return handleWebDavMove(req, env, url, internalPath);
    case "COPY":
      return handleWebDavCopy(req, env, url, internalPath);
    default:
      // ── B1 修复：405 必须带 Allow 头（RFC 7231 MUST） ──
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY" },
      });
  }
}

/* ═══════════ PROPFIND ═══════════ */

async function handlePropfind(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const depth = req.headers.get("depth") || "1"; // 0 / 1 / infinity
  const baseUrl = url.origin;

  const pathExists = await directoryExists(env, internalPath);
  const file = pathExists && internalPath !== "/"
    ? await env.db
        .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path = ?1 AND name = ?2")
        .bind(internalPath.slice(0, internalPath.lastIndexOf("/")) || "/",
              internalPath.split("/").filter(Boolean).pop() || "")
        .first<DBFile>()
    : null;

  // 检查这到底是个文件还是目录
  if (file && file.path === internalPath) {
    // 这是个文件
    const href = buildHref(baseUrl, internalPath);
    const body = multistatusXML([filePropstatAsFile(file, href)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // 应该是目录
  if (!pathExists) {
    return new Response("Not Found", { status: 404 });
  }

  // Depth: 0 —— 只返回目录自身
  if (depth === "0") {
    const body = multistatusXML([dirPropstat(internalPath, baseUrl)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // Depth: 1 或 infinity —— 返回目录自身 + 子项
  const responses: string[] = [dirPropstat(internalPath, baseUrl)];

  if (depth === "1") {
    const { files, dirs } = await listDirChildren(env, internalPath);
    for (const d of dirs) {
      responses.push(dirPropstat(d, baseUrl));
    }
    for (const f of files) {
      // 文件的 href 不带尾斜杠（RFC 4918），并做 URL 编码
      const href = buildHref(baseUrl, f.path, false);
      responses.push(filePropstatAsFile(f, href));
    }
  } else {
    // infinity —— 递归列出所有
    await collectAll(env, internalPath, baseUrl, responses);
  }

  const body = multistatusXML(responses);
  return new Response(body, {
    status: 207,
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
}

/** 递归收集目录下所有子项（Depth: infinity）
 *  硬上限：深度 16 / 条目 5000，超限提前返回已收集部分（选返回部分而非 403，避免客户端丢弃已取数据） */
async function collectAll(
  env: Env,
  path: string,
  baseUrl: string,
  responses: string[],
  depth = 0
): Promise<void> {
  if (depth >= 16) return;
  if (responses.length >= 5000) return;
  const { files, dirs } = await listDirChildren(env, path);
  for (const d of dirs) {
    if (responses.length >= 5000) return;
    responses.push(dirPropstat(d, baseUrl));
    await collectAll(env, d, baseUrl, responses, depth + 1);
  }
  for (const f of files) {
    if (responses.length >= 5000) return;
    // 文件的 href 不带尾斜杠（RFC 4918），并做 URL 编码
    const href = buildHref(baseUrl, f.path, false);
    responses.push(filePropstatAsFile(f, href));
  }
}

/* ═══════════ GET / HEAD ═══════════ */

async function handleWebDavGet(
  req: Request,
  env: Env,
  internalPath: string,
  headOnly: boolean
): Promise<Response> {
  // 拆分为 dir + name
  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  if (!name) {
    // 目录 —— 本实现不提供 GET 目录列表。
    // ── B6 修复：GET 一个集合常规应返回 405（并带 Allow），原为 409（语义是"冲突"，误导客户端）
    return new Response("Method Not Allowed: cannot GET a collection", {
      status: 405,
      headers: { Allow: "PROPFIND, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, OPTIONS" },
    });
  }

  const file = await findFile(env, dir, name);
  if (!file) {
    return new Response("Not Found", { status: 404 });
  }

  const st = await storage(env);
  const obj = await st.head(file.key);
  if (!obj) {
    return new Response("Not Found", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", obj.contentType);
  headers.set("Content-Length", String(obj.size));
  headers.set("ETag", `"${file.id}"`);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", tsToRfc1123(file.uploaded_at));
  headers.set("Cache-Control", "no-store");
  // 防同源内联渲染 XSS —— 危险类型强制附件下载，所有响应加 nosniff
  headers.set("X-Content-Type-Options", "nosniff");
  const baseType = (obj.contentType || "").split(";")[0].trim().toLowerCase();
  if (["text/html", "image/svg+xml", "application/xhtml+xml", "text/xml", "application/xml"].includes(baseType)) {
    headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
  }

  if (headOnly) {
    return new Response("", { status: 200, headers });
  }

  // 支持 Range 请求
  const rangeHeader = req.headers.get("range");
  if (rangeHeader) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
    if (m) {
      let offset = m[1] === "" ? null : Number(m[1]);
      let end = m[2] === "" ? null : Number(m[2]);
      if (offset === null && end !== null) {
        // 后缀范围 bytes=-N —— N 超过文件大小时钳到 0，按 RFC 返回整个文件
        offset = Math.max(0, obj.size - end);
        end = obj.size - 1;
      } else if (offset !== null) {
        if (end === null) end = obj.size - 1;
        if (end >= obj.size) end = obj.size - 1;
        if (offset > end) {
          return new Response("Range Not Satisfiable", { status: 416, headers: { "Content-Range": `bytes */${obj.size}` } });
        }
      }
      if (offset !== null && end !== null) {
        const len = end - offset + 1;
        headers.set("Content-Range", `bytes ${offset}-${end}/${obj.size}`);
        headers.set("Content-Length", String(len));
        const ranged = await st.get(file.key, { offset, length: len });
        if (!ranged) return new Response("Not Found", { status: 404 });
        return new Response(ranged.body, { status: 206, headers });
      }
    }
  }

  const fullObj = await st.get(file.key);
  if (!fullObj) return new Response("Not Found", { status: 404 });
  return new Response(fullObj.body, { status: 200, headers });
}

/* ═══════════ PUT ═══════════ */

async function handleWebDavPut(
  req: Request,
  env: Env,
  internalPath: string
): Promise<Response> {
  // 拆分为 dir + name
  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  if (!name) {
    return new Response("No file name", { status: 400 });
  }

  // 父目录必须存在
  if (!(await directoryExists(env, dir))) {
    return new Response("Conflict: parent directory does not exist", { status: 409 });
  }

  // 目标本身是目录时禁止 PUT（405），否则 files/directories 同路径并存，PROPFIND 把目录当文件
  if ((await directoryExists(env, internalPath)) && !(await pathIsFile(env, internalPath))) {
    return new Response("Method Not Allowed: destination is a collection", { status: 405 });
  }

  const mime = req.headers.get("content-type") || "application/octet-stream";
  const st = await storage(env);

  // 生成文件记录
  const id = randomId(14);
  const key = `files/${id}`;
  const now = Date.now();

  let size = 0;
  try {
    const res = await st.put(key, req.body as any, {
      contentType: mime,
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
    });
    size = res.size;
  } catch (err: any) {
    console.error("[webdav] storage put failed:", err);
    return new Response("Storage error", { status: 502 });
  }

  // 检查是否已存在同名文件（覆盖）
  const existing = await findFile(env, dir, name);

  // 先插入新记录，成功后再清理旧记录，避免覆盖失败时原文件永久丢失
  const fullPath = dir === "/" ? `/${name}` : `${dir}/${name}`;
  try {
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, path, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(id, key, name, size, mime, fullPath, now).run();
  } catch (err: any) {
    // D1 失败 —— 清理 storage
    await st.delete(key).catch(() => {});
    console.error("[webdav] DB error:", err);
    return new Response("Database error", { status: 502 });
  }

  if (existing) {
    // 删除旧文件 + 关联的 shares（新旧对象 key 相同时跳过，避免误删刚写入的新对象）
    try {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(existing.id),
      ]);
      if (existing.key !== key) await st.delete(existing.key).catch(() => {});
    } catch { /* 忽略清理失败 */ }
  }

  return new Response("", {
    status: existing ? 204 : 201,
    headers: { "ETag": `"${id}"` },
  });
}

/* ═══════════ DELETE ═══════════ */

async function handleWebDavDelete(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Cannot delete root", { status: 403 });
  }

  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  // 1. 先看是不是文件
  if (name) {
    const file = await findFile(env, dir, name);
    if (file) {
      const st = await storage(env);
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(file.id),
      ]);
      await st.delete(file.key).catch(() => {});
      return new Response("", { status: 204 });
    }
  }

  // 2. 看看是不是目录
  if (await directoryExists(env, internalPath)) {
    // 递归删除目录下所有文件
    const st = await storage(env);
    const likePattern = likeEscape(internalPath) + "/%";
    const { results: files } = await env.db
      .prepare("SELECT id, key FROM files WHERE path LIKE ?1 ESCAPE '\\'")
      .bind(likePattern)
      .all<{ id: string; key: string }>();

    for (const f of files) {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(f.id),
      ]);
      await st.delete(f.key).catch(() => {});
    }

    // 删除目录本身及全部后代目录记录，避免残留「幽灵目录」
    await env.db
      .prepare("DELETE FROM directories WHERE path = ?1 OR path LIKE ?2 ESCAPE '\\'")
      .bind(internalPath, likeEscape(internalPath) + "/%").run();

    return new Response("", { status: 204 });
  }

  return new Response("Not Found", { status: 404 });
}

/* ═══════════ MKCOL ═══════════ */

async function handleWebDavMkcol(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Root exists", { status: 200 });
  }

  // 父目录必须存在
  const parent = internalPath.slice(0, internalPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, parent))) {
    return new Response("Conflict: parent does not exist", { status: 409 });
  }

  // 目标不能是已存在的文件
  const lastSlash = internalPath.lastIndexOf("/");
  const pdir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const pname = internalPath.slice(lastSlash + 1);
  if (pname) {
    const existingFile = await findFile(env, pdir, pname);
    if (existingFile) {
      return new Response("Method Not Allowed: file exists here", { status: 405 });
    }
  }

  // ── B6 修复：目标目录已存在 → RFC 4918 要求 405（Method Not Allowed）──
  // 原来直接 INSERT ... ON CONFLICT DO NOTHING 后无条件返回 201，
  // 客户端会以为目录是新建的（实际没建），重试逻辑与缓存都会错乱。
  if (await directoryExists(env, internalPath)) {
    return new Response("Method Not Allowed: collection already exists", { status: 405 });
  }

  try {
    await env.db.prepare(
      "INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING"
    ).bind(internalPath, Date.now()).run();
  } catch (err: any) {
    console.error("[webdav] DB error:", err);
    return new Response("Database error", { status: 502 });
  }

  return new Response("", { status: 201 });
}

/* ═══════════ MOVE ═══════════ */

async function handleWebDavMove(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  // 从 Destination URL 提取目标路径
  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  // 禁止移动根目录：moveDirectory 的 LIKE "/%" 会命中全部文件，整库 path 被重写
  if (internalPath === "/") {
    return new Response("Cannot move root", { status: 403 });
  }

  // ── 漏修项补全：MOVE 到自身 / 移到自己的子路径下 → 409（RFC 4918）──
  // 原实现会先执行 `handleWebDavDelete(destPath)`：当 destPath === internalPath 时
  // **删的就是源本身**，随后 moveFile 找不到源静默返回，最终回 204 —— 文件凭空消失。
  // 目标位于源之下（把 /a 移到 /a/b）同样是先毁源、再把路径改写成错乱前缀。
  if (destPath === internalPath) {
    return new Response("Conflict: destination is the same as source", { status: 409 });
  }
  if (destPath.startsWith(internalPath + "/")) {
    return new Response("Conflict: cannot move a collection into itself", { status: 409 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  // 检查源是否存在
  const srcExists = await directoryExists(env, internalPath);
  const srcFile = await pathIsFile(env, internalPath);
  if (!srcExists && !srcFile) {
    return new Response("Not Found", { status: 404 });
  }

  // 目标父目录必须存在
  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  // 检查目标是否存在
  const destExists = await directoryExists(env, destPath);
  const destFile = await pathIsFile(env, destPath);
  if ((destExists || destFile) && !overwrite) {
    return new Response("Precondition Failed: destination exists", { status: 412 });
  }

  // 如果目标已存在，先删除
  if (destExists || destFile) {
    await handleWebDavDelete(env, destPath);
  }

  if (srcFile) {
    // 移动文件
    await moveFile(env, internalPath, destPath);
  } else {
    // 移动目录（递归更新 path）
    await moveDirectory(env, internalPath, destPath);
  }

  return new Response("", { status: destExists || destFile ? 204 : 201 });
}

/* ═══════════ COPY ═══════════ */

async function handleWebDavCopy(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  // ── 漏修项补全：COPY 到自身 → 409 ──
  // COPY 与 MOVE 共用「先删目标再写入」的流程：destPath === internalPath 时，
  // 删掉的正是源文件，随后 st.get(srcFile.key) 拿不到对象 → 返回 404，源文件已毁。
  if (destPath === internalPath) {
    return new Response("Conflict: destination is the same as source", { status: 409 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  const srcFile = await pathIsFile(env, internalPath);
  if (!srcFile) {
    return new Response("Only file copy supported", { status: 501 });
  }

  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  const destFile = await pathIsFile(env, destPath);
  // 目标命中目录（含 Overwrite: F）时返回 412；Overwrite: T 也不许文件覆盖集合（409），
  // 避免 files/directories 同路径并存
  const destIsDir = !destFile && (await directoryExists(env, destPath));
  // ── B6 修复：记下目标原本是否存在，用于区分 201 Created / 204 No Content ──
  const destExisted = !!(destFile || destIsDir);
  if (destFile || destIsDir) {
    if (!overwrite) {
      return new Response("Precondition Failed: destination exists", { status: 412 });
    }
    if (destIsDir) {
      return new Response("Conflict: destination is a collection", { status: 409 });
    }
    await handleWebDavDelete(env, destPath);
  }

  const st = await storage(env);
  const srcObj = await st.get(srcFile.key);
  if (!srcObj) return new Response("Source not found", { status: 404 });

  const newId = randomId(14);
  const newKey = `files/${newId}`;
  const newName = destPath.split("/").filter(Boolean).pop() || srcFile.name;

  // put 与 INSERT 同包 try/catch：任一步失败清理新对象，避免留下孤儿存储对象
  try {
    await st.put(newKey, srcObj.body, { contentType: srcFile.mime });
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, path, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(newId, newKey, newName, srcFile.size, srcFile.mime, destPath, Date.now()).run();
  } catch (err: any) {
    await st.delete(newKey).catch(() => {});
    console.error("[webdav] copy failed:", err);
    return new Response("Copy failed", { status: 502 });
  }

  // ── B6 修复：覆盖已有资源应返回 204 No Content，只有新建才是 201 Created ──
  return new Response("", { status: destExisted ? 204 : 201 });
}

/* ═══════════ 辅助：判断路径是否是文件 ═══════════ */

async function pathIsFile(env: Env, p: string): Promise<DBFile | null> {
  const lastSlash = p.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : p.slice(0, lastSlash);
  const name = p.slice(lastSlash + 1);
  if (!name) return null;
  return await findFile(env, dir, name);
}

/* ═══════════ 辅助：移动文件 ═══════════ */

async function moveFile(env: Env, srcPath: string, destPath: string): Promise<void> {
  const srcLast = srcPath.lastIndexOf("/");
  const srcDir = srcLast <= 0 ? "/" : srcPath.slice(0, srcLast);
  const srcName = srcPath.slice(srcLast + 1);

  const file = await findFile(env, srcDir, srcName);
  if (!file) return;

  const destLast = destPath.lastIndexOf("/");
  const destDir = destLast <= 0 ? "/" : destPath.slice(0, destLast);
  const destName = destPath.slice(destLast + 1);
  const fullDestPath = destDir === "/" ? `/${destName}` : `${destDir}/${destName}`;

  await env.db.prepare(
    "UPDATE files SET path = ?1, name = ?2 WHERE id = ?3"
  ).bind(fullDestPath, destName, file.id).run();
}

/* ═══════════ 辅助：移动目录（递归更新 path 前缀） ═══════════ */

async function moveDirectory(env: Env, srcDir: string, destDir: string): Promise<void> {
  const likePattern = srcDir === "/" ? "/%" : likeEscape(srcDir) + "/%";
  const { results: files } = await env.db
    .prepare("SELECT id, path FROM files WHERE path LIKE ?1 ESCAPE '\\'")
    .bind(likePattern)
    .all<{ id: string; path: string }>();

  // 也查出 directories 表中的子目录记录（先查后统一 batch）
  const { results: dirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ?1 ESCAPE '\\'")
    .bind(likePattern)
    .all<{ path: string }>();

  // 全部语句收集后一次 batch 提交，保证原子性，失败不留半迁移状态
  const stmts: any[] = [];

  for (const f of files) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + f.path;
      if (!newPath.startsWith("/")) newPath = "/" + newPath;
    } else {
      newPath = destDir + f.path.slice(srcDir.length);
    }
    stmts.push(env.db.prepare("UPDATE files SET path = ?1 WHERE id = ?2").bind(newPath, f.id));
  }

  for (const d of dirs) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + d.path;
    } else {
      newPath = destDir + d.path.slice(srcDir.length);
    }
    stmts.push(env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(d.path));
    stmts.push(
      env.db.prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
        .bind(newPath, Date.now())
    );
  }

  // 更新目录本身
  stmts.push(env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(srcDir));
  stmts.push(
    env.db.prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
      .bind(destDir, Date.now())
  );

  await env.db.batch(stmts);
}
