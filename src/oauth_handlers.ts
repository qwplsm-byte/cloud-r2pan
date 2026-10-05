/**
 * OAuth2 HTTP 处理函数 —— 多 Provider 模式
 *
 * 路由:
 *   GET  /oauth/start?provider=xxx          → 重定向到 Provider 授权页
 *   GET  /oauth/callback?code=...&state=...  → Provider 回调
 *   GET  /oauth/session                     → 返回当前 OAuth 会话状态
 *   POST /oauth/logout                      → 清除 OAuth Cookie
 *   GET  /oauth/providers                   → 返回所有启用的 Provider 列表（给分享页渲染按钮）
 *
 * 所有 Provider 配置均来自 D1 的 oauth_providers 表。
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { decryptSecret, safeEqual } from "./crypto";
import { clientIp } from "./auth";
import {
  getBuiltinProvider,
  BUILTIN_PROVIDERS,
  createOAuthState,
  verifyOAuthState,
  buildAuthorizeUrl,
  exchangeCode,
  fetchUserInfo,
  signOAuthSession,
  verifyOAuthSession,
  deriveRedirectUri,
  generateCodeVerifier,
  sha256Base64Url,
  type OAuthProvider,
} from "./oauth";

/* ═══════════ 从 D1 构造 OAuthProvider ═══════════ */

interface OAuthProviderRow {
  id: string;
  label: string;
  provider_type: string;
  client_id: string;
  client_secret_cipher: string | null;
  scope: string;
  custom_authorize_url: string;
  custom_token_url: string;
  custom_userinfo_url: string;
  custom_token_field: string;
  enabled: number;
}

function rowToProvider(row: OAuthProviderRow): OAuthProvider | null {
  const base = getBuiltinProvider(row.provider_type);
  if (!base) return null;
  if (row.provider_type === "custom") {
    // 自定义 Provider —— 必填所有 URL
    if (!row.custom_authorize_url || !row.custom_token_url || !row.custom_userinfo_url) return null;
    return {
      id: row.provider_type,
      name: row.label || "Custom",
      authorize_url: row.custom_authorize_url,
      token_url: row.custom_token_url,
      userinfo_url: row.custom_userinfo_url,
      default_scope: row.scope || "openid email profile",
      token_field: row.custom_token_field || "access_token",
    };
  }
  return { ...base, default_scope: row.scope || base.default_scope };
}

async function fetchProviderRow(env: Env, dbId: string): Promise<OAuthProviderRow | null> {
  const row = await env.db
    .prepare("SELECT id, label, provider_type, client_id, client_secret_cipher, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled FROM oauth_providers WHERE id = ?1")
    .bind(dbId)
    .first<OAuthProviderRow>();
  return row ?? null;
}

async function listEnabledProviders(env: Env): Promise<OAuthProviderRow[]> {
  const rows = await env.db
    .prepare("SELECT id, label, provider_type, client_id, client_secret_cipher, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled FROM oauth_providers WHERE enabled = 1")
    .all<OAuthProviderRow>();
  return rows.results;
}

/* ═══════════ GET /oauth/providers —— 分享页用 ═══════════
 * 返回启用中的 Provider 列表（不含敏感信息，只够渲染按钮）。
 * 如果 settings.oauth_enabled=false 则返回空数组。
 */
export async function handleOAuthProviders(req: Request, env: Env): Promise<Response> {
  const settings = await getSettings(env);
  if (!settings.oauthEnabled) return Response.json({ providers: [], enabled: false });
  const rows = await listEnabledProviders(env);
  const origin = new URL(req.url).origin;
  const providers = rows
    .filter((r) => r.client_id) // 没有 client_id 的不能用
    .map((r) => {
      const p = rowToProvider(r);
      return {
        id: r.id,
        label: r.label,
        provider_type: r.provider_type,
        name: p?.name ?? r.provider_type,
        start_url: `/oauth/start?provider=${encodeURIComponent(r.id)}`,
        client_id: r.client_id,
      };
    });
  return Response.json({ providers, enabled: providers.length > 0 });
}

/* ═══════════ /oauth/start 限流（isolate 内存，写法沿用 auth.ts 的 rateLimitLogin）═══════════
 * ── M-5B 修复：原实现每请求一次 INSERT，无限流可被刷爆 oauth_states 表。
 * 同一 IP 1 分钟窗口内最多 10 次，超出返回 429。
 * ⚠️ Worker 无状态，计数随 isolate 重启清空（与项目其他限流一致，只加重刷成本）。
 */
const OAUTH_START_LIMIT = 10;
const OAUTH_START_WINDOW_MS = 60_000;
const oauthStartAttempts = new Map<string, { count: number; resetAt: number }>();
let oauthStartSweepCount = 0;

function rateLimitOAuthStart(ip: string): boolean {
  const now = Date.now();
  const rec = oauthStartAttempts.get(ip);
  if (!rec || rec.resetAt < now) {
    if (rec) oauthStartAttempts.delete(ip);
    oauthStartAttempts.set(ip, { count: 1, resetAt: now + OAUTH_START_WINDOW_MS });
  } else {
    rec.count++;
  }
  // 每 100 次调用触发一次全量 sweep，防止过期 entry 累积占内存
  if (++oauthStartSweepCount % 100 === 0) {
    for (const [key, val] of oauthStartAttempts) {
      if (val.resetAt < now) oauthStartAttempts.delete(key);
    }
  }
  return oauthStartAttempts.get(ip)!.count <= OAUTH_START_LIMIT;
}

/* ═══════════ GET /oauth/start?provider=<provider_id>&redirect=<path> ═══════════ */
export async function handleOAuthStart(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const providerDbId = url.searchParams.get("provider") || "";
  const redirectTo = url.searchParams.get("redirect") || "/";

  // ── M-5B：/oauth/start 限流，防每请求一次 INSERT 撑爆 oauth_states ──
  if (!rateLimitOAuthStart(clientIp(req))) {
    return Response.json(
      { error: "rate_limited", message: "请求过于频繁，请稍后再试" },
      { status: 429, headers: { "Retry-After": String(OAUTH_START_WINDOW_MS / 1000) } }
    );
  }

  const settings = await getSettings(env);
  if (!settings.oauthEnabled) {
    return Response.json({ error: "oauth_disabled" }, { status: 400 });
  }

  const row = await fetchProviderRow(env, providerDbId);
  if (!row || !row.enabled) {
    return Response.json({ error: "provider_not_found_or_disabled" }, { status: 400 });
  }
  if (!row.client_id) {
    return Response.json({ error: "client_id_missing" }, { status: 500 });
  }

  const provider = rowToProvider(row);
  if (!provider) {
    return Response.json({ error: "provider_broken" }, { status: 500 });
  }

  const redirectUri = deriveRedirectUri(req);
  // state 里存 D1 provider 的 db id，callback 时直接查回完整 provider
  const state = await createOAuthState(env, row.id, redirectUri);

  // ── M-2 修复：PKCE + state 绑定浏览器（防登录 CSRF）──
  // code_verifier 只进 HttpOnly cookie，不进 URL；authorize 只带 S256 挑战值。
  // state 同名一次性 cookie 下发给发起登录的浏览器，callback 时比对，防止攻击者
  // 拿自己流程里的 code+state 塞进受害者浏览器完成「登录 CSRF」。
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const authorizeUrl = buildAuthorizeUrl(
    provider,
    row.client_id,
    redirectUri,
    row.scope || provider.default_scope,
    state,
    codeChallenge
  );

  // ── L-4：cd_oauth_redirect 补 Secure（HTTPS 下）──
  const secureAttr = url.protocol === "https:" ? "; Secure" : "";
  // ── M-4 同理：多个 Set-Cookie 必须各自成头，不能逗号拼接（RFC 6265）──
  const h = new Headers();
  h.set("location", authorizeUrl);
  h.append(
    "set-cookie",
    `cd_oauth_redirect=${encodeURIComponent(redirectTo)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureAttr}`
  );
  h.append("set-cookie", `cd_oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureAttr}`);
  h.append("set-cookie", `cd_oauth_pkce=${codeVerifier}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${secureAttr}`);
  return new Response(null, { status: 302, headers: h });
}

/* ═══════════ GET /oauth/callback ═══════════ */
export async function handleOAuthCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  const error = url.searchParams.get("error");
  if (error) {
    return redirectBackWithMsg(req, "oauth_error: " + error);
  }
  if (!code || !state) {
    return redirectBackWithMsg(req, "oauth_missing_code");
  }

  const cookieHeader = req.headers.get("cookie");
  // ── M-2 修复：state 必须与发起登录的那个浏览器绑定（一次性 HttpOnly cookie）──
  // 放在消费 state 之前校验：比对失败时不消耗合法 state，避免被刷掉。
  const boundState = parseCookie(cookieHeader, "cd_oauth_state");
  if (!boundState || !safeEqual(boundState, state)) {
    return redirectBackWithMsg(req, "oauth_state_unbound");
  }
  // ── M-2：PKCE code_verifier 只存在于发起登录的浏览器，缺失即拒绝 ──
  const codeVerifier = parseCookie(cookieHeader, "cd_oauth_pkce");
  if (!codeVerifier) {
    return redirectBackWithMsg(req, "oauth_pkce_missing");
  }

  // 1. 校验 state（一次性消费 + TTL，单条 DELETE ... RETURNING 原子完成）
  const verify = await verifyOAuthState(env, state);
  if (!verify.ok || !verify.provider_id) {
    return redirectBackWithMsg(req, "oauth_state_invalid");
  }

  // 从 state 拿的是 provider_type（github/google...），我们需要回查 Db 里对应的 enabled provider
  // 但 state 存的是 provider_type，可能有多个同类型 provider。我们改用：state 里存 db id
  // 让我们调整 state 里的 provider_id 语义 —— 现在的 createOAuthState 存 provider_type
  // 改为存 db id
  // 但改动 createOAuthState 会影响 state 结构...让我们看看 state 表
  // CREATE TABLE oauth_states(state TEXT, provider_id TEXT, redirect_uri TEXT, expires_at INTEGER)
  // provider_id 现在存的是 provider_type。我们改成存 db id。
  // 但 handleOAuthStart 里已经在 createOAuthState 时用了 provider_type。
  // 让我们改 handleOAuthStart 的调用：createOAuthState(env, providerDbId, redirectUri)
  // 然后这里直接 fetchProviderRow(env, verify.provider_id) 即可
  // （我们已经在 handleOAuthStart 里把 providerDbId 传进去了，看看：）

  // 好，现在 provider_id 字段存的是 D1 里的 provider db id，直接查
  const providerDbId = verify.provider_id;
  const row = await fetchProviderRow(env, providerDbId);
  if (!row) {
    return redirectBackWithMsg(req, "oauth_provider_missing");
  }
  // ── M-3 相关：/oauth/start 已查 enabled，callback 必须复查 ──
  // 否则「start 之后被管理员禁用」或 state 伪造成功时，已禁用 provider 仍能完成登录。
  if (!row.enabled) {
    return redirectBackWithMsg(req, "oauth_provider_disabled");
  }
  const provider = rowToProvider(row);
  if (!provider) {
    return redirectBackWithMsg(req, "oauth_provider_broken");
  }
  if (!row.client_secret_cipher) {
    return redirectBackWithMsg(req, "oauth_credentials_missing");
  }

  // 2. 解密 Client Secret
  const clientSecret = await decryptSecret(row.client_secret_cipher, env.admin);
  if (!clientSecret) {
    return redirectBackWithMsg(req, "oauth_secret_decrypt_failed");
  }

  // 3. code → access_token
  const redirectUri = verify.redirect_uri!;
  const token = await exchangeCode(provider, code, redirectUri, row.client_id, clientSecret, codeVerifier);
  if (!token) {
    return redirectBackWithMsg(req, "oauth_exchange_failed");
  }

  // 4. 拉用户信息
  const user = await fetchUserInfo(provider, token.accessToken);
  if (!user) {
    return redirectBackWithMsg(req, "oauth_userinfo_failed");
  }

  // 5. 发 OAuth 会话 Cookie
  // cookie 里存的是 db id，方便 later check 时知道用的是哪个 provider
  const { cookie, secure } = await signOAuthSession(env, providerDbId, user.id);
  // ── H10 修复：回跳目标白名单（防开放重定向 / 钓鱼） ──
  // cd_oauth_redirect cookie 在 /oauth/start 时由攻击者可控的 ?redirect= 写入，
  // 原实现把它的值原样塞进 location 做 302，可构造
  //   /oauth/start?provider=<id>&redirect=https%3A%2F%2Fevil.com
  // 或 redirect=//evil.com，完成登录后把用户送到钓鱼站。
  // 错误分支本来就有 new URL() 取 pathname 的防护，成功路径却没有。
  // 这里只放行「同源站内路径」：必须以单个 / 开头（排除 //、/\）。
  const originalRedirect = safeLocalRedirect(parseCookie(req.headers.get("cookie"), "cd_oauth_redirect"));

  const setCookieParts: string[] = [cookie, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=3600"];
  if (url.protocol === "https:" && secure) setCookieParts.push("Secure");
  const setCookie = setCookieParts.join("; ");

  // ── M-4 修复：原来用 `["a","b"].join(", ")` 拼成一个 set-cookie 头，违反 RFC 6265 ──
  // 部分解析器会把它当成一个 Cookie，导致 cd_oauth_redirect 清不掉 / 丢 Secure。
  // 改为多次 append，让每个 Set-Cookie 独立成头（CF Workers 的 Headers 支持多次 append）。
  const h = new Headers();
  h.set("location", originalRedirect);
  h.append("set-cookie", setCookie);
  h.append("set-cookie", "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  h.append("set-cookie", "cd_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  h.append("set-cookie", "cd_oauth_pkce=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");

  return new Response(null, { status: 302, headers: h });
}

/* ═══════════ GET /oauth/session ═══════════ */
export async function handleOAuthSession(req: Request, env: Env): Promise<Response> {
  const result = await verifyOAuthSession(env, req.headers.get("cookie"));
  if (!result.ok) {
    return Response.json({ authenticated: false });
  }
  // 查 provider 类型用于前端显示
  const row = await fetchProviderRow(env, result.providerId);
  return Response.json({
    authenticated: true,
    provider_db_id: result.providerId,
    provider_type: row?.provider_type ?? "unknown",
    provider_label: row?.label ?? result.providerId,
    user_id: result.userId,
  });
}

/* ═══════════ POST /oauth/logout ═══════════ */
export async function handleOAuthLogout(req: Request): Promise<Response> {
  // ── L-6 修复：仅接受 POST，防「<img src=/oauth/logout>」式的 CSRF 强制登出 ──
  // 前端 share.html 用 fetch POST 调用；index.ts 仍会把 GET 转进来，这里兜底拒绝。
  if (req.method !== "POST") {
    return Response.json(
      { ok: false, error: "method_not_allowed" },
      { status: 405, headers: { allow: "POST" } }
    );
  }
  const url = new URL(req.url);
  const secure = url.protocol === "https:";
  const cookie = `cd_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "set-cookie": cookie,
      "cache-control": "no-store",
    },
  });
}

/* ═══════════ 辅助函数 ═══════════ */

/**
 * ── H10 修复 ──
 * 把回跳目标限制为同源站内路径，防止开放重定向钓鱼。
 *   "https://evil.com/..." → "/"   （绝对 URL，拒绝）
 *   "//evil.com"          → "/"   （协议相对，浏览器会当外站，拒绝）
 *   "/\\evil.com"         → "/"   （部分浏览器把 \/ 当 // 解析，拒绝）
 *   "/s/abc?x=1"          → 原样返回（站内路径，放行）
 */
function safeLocalRedirect(raw: string): string {
  const v = (raw || "").trim();
  if (!v.startsWith("/")) return "/";
  if (v.startsWith("//") || v.startsWith("/\\")) return "/";
  return v;
}

function parseCookie(header: string | null, name: string): string {
  if (!header) return "";
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`);
  const m = re.exec(header);
  if (!m) return "";
  // ── L-5 修复：非法 % 序列会让 decodeURIComponent 抛异常 → 500，失败回退原值 ──
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return m[1];
  }
}

function redirectBackWithMsg(req: Request, msg: string): Response {
  const redirectTo = parseCookie(req.headers.get("cookie"), "cd_oauth_redirect") || "/";
  // ── L-5 修复：new URL 可能抛异常（500），失败统一回退到 / ──
  let target = `/?oauth_error=${encodeURIComponent(msg)}`;
  try {
    const url = new URL(redirectTo, "https://localhost");
    url.searchParams.set("oauth_error", msg);
    target = `${url.pathname}${url.search}`;
  } catch {
    // 保留 encodeURIComponent 版本的兜底地址
  }
  const setCookie = "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
  return new Response(null, {
    status: 302,
    headers: {
      location: target,
      "set-cookie": setCookie,
    },
  });
}
