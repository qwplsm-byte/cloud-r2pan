import type { Env } from "./types";
import { createStorageProvider } from "./storage";
import { getSettings } from "./settings";
import { purgeExpiredOAuthStates } from "./oauth";

/**
 * 可复用的清理逻辑 —— 供两处调用：
 * 1. 管理后台手动清理 API（POST /api/admin/shares/cleanup 等）
 * 2. Cron Trigger 每日自动清理（index.ts 的 scheduled handler）
 */

/**
 * 孤儿文件判定的「上传宽限期」。
 *
 * ── C2 修复（不可恢复的数据丢失）────────────────────────────────
 * 原查询只判「没有任何 share / direct_link 引用」，既不过滤也不等待，每日 cron
 * 会把下列本应保留的文件连同 R2 对象一起永久删除：
 *   ① 通过 WebDAV 挂载写入的文件 —— 它们只 INSERT files、永远不会创建 share
 *   ② 刚上传、还没来得及调创建分享接口的文件 —— 上传与建分享是两个独立接口，
 *      两者之间存在时间窗口，cron 落在窗口内即销毁
 * 修复：排除非 '/' 路径的文件（WebDAV 托管），并给上传加 7 天宽限期。
 */
const ORPHAN_UPLOAD_GRACE_MS = 7 * 24 * 3600 * 1000;

/**
 * 单轮最多回收多少个孤儿文件、以及 IN 子句的分批大小。
 * ── M-8 修复 ──
 * D1 单查询的绑定参数有上限，原实现把全部 id 一把拼进 `IN (...)`：
 * 孤儿一多就整批 SQL 报错，**整个清理直接失效**。这里分批 + 每轮封顶，
 * 超出部分留给下一次 cron，既不会撞参数上限，也不会让一次清理跑太久。
 */
const ORPHAN_MAX_PER_RUN = 300;
const ORPHAN_DELETE_CHUNK = 100;

/** 清理失效分享（过期 / 已撤销 / 达上限）+ 孤儿文件 + 孤儿存储对象 */
export async function cleanupExpiredShares(
  env: Env,
  ctx: ExecutionContext
): Promise<{ deleted_shares: number; deleted_orphan_files: number }> {
  const now = Date.now();

  // 0. 【必须排在删除分享之前】先取孤儿快照 —— C2 修复 ——
  //    原实现先删失效分享、再在同一轮里查孤儿，于是分享一过期，它的唯一文件立刻
  //    被判为孤儿并连同存储对象销毁（把「分享过期」升级成「源文件永久删除」）。
  //    先取快照再删分享后，这批文件至少能保留一个清理周期，给管理员补救窗口。
  const orphans = await env.db.prepare(
    `SELECT f.id, f.key FROM files f
     LEFT JOIN shares s ON s.file_id = f.id
     LEFT JOIN direct_links d ON d.file_id = f.id
     WHERE s.id IS NULL AND d.id IS NULL
       AND (f.path IS NULL OR f.path = '/')
       AND f.uploaded_at < ?1`
  ).bind(now - ORPHAN_UPLOAD_GRACE_MS).all<{ id: string; key: string }>();

  const orphanIds = (orphans.results ?? []).map((o) => o.id);
  const orphanKeys = (orphans.results ?? []).map((o) => o.key);

  // 1. 删除失效 shares
  const deleted = await env.db.prepare(
    "DELETE FROM shares WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)"
  )
    .bind(now)
    .run();

  // 2. 回收孤儿文件 —— **先删存储对象，对象删成功才删 DB 行**
  //    ── M-9 修复 ── 原实现先删 DB 行、再把对象删除挂到 waitUntil 里静默容错：
  //    一旦对象删除失败，该 key 已无任何 DB 引用 → 之后再也查不到、永远无法清理，
  //    成为「永久孤儿对象」持续计费。现在反过来，失败就保留 DB 记录、下轮重试 ——
  //    最坏只是多留一条记录（可再删），绝不会留下无法追踪的对象。
  //
  //    另外按常量分批：D1 单查询的绑定参数有上限，一次几千个 id 拼进 IN 会让**整批**报错，
  //    反而使清理完全失效（原实现就是一把梭）。
  let deletedOrphans = 0;
  if (orphanIds.length > 0) {
    let st: Awaited<ReturnType<typeof createStorageProvider>> | null = null;
    try {
      st = await createStorageProvider(env, await getSettings(env));
    } catch (e) {
      // 存储配置不可用 → 整体跳过文件回收，绝不能「删了行却删不掉对象」
      console.error("cleanup: storage provider unavailable, skip orphan purge:", e);
    }

    if (st) {
      const okIds: string[] = [];
      // 每批并发 10 个对象删除，最多处理 ORPHAN_MAX_PER_RUN 个，剩余留给下一轮
      for (let i = 0; i < orphanIds.length && okIds.length < ORPHAN_MAX_PER_RUN; i += 10) {
        const idxs = [];
        for (let j = i; j < i + 10 && j < orphanIds.length && okIds.length + idxs.length < ORPHAN_MAX_PER_RUN; j++) {
          idxs.push(j);
        }
        const results = await Promise.all(
          idxs.map(async (j) => {
            try {
              await st!.delete(orphanKeys[j]);
              return orphanIds[j];
            } catch {
              return null; // 删不掉 → 保留该文件记录，下轮重试
            }
          })
        );
        for (const id of results) if (id) okIds.push(id);
      }

      // 对象已删干净，才删 DB 行（按 chunk 分批，避免超出绑定参数上限）
      for (let i = 0; i < okIds.length; i += ORPHAN_DELETE_CHUNK) {
        const chunk = okIds.slice(i, i + ORPHAN_DELETE_CHUNK);
        const placeholders = chunk.map((_, j) => `?${j + 1}`).join(", ");
        await env.db.batch([
          env.db.prepare(`DELETE FROM download_logs WHERE file_id IN (${placeholders})`).bind(...chunk),
          env.db.prepare(`DELETE FROM files WHERE id IN (${placeholders})`).bind(...chunk),
        ]);
      }
      deletedOrphans = okIds.length;
    }
  }

  return { deleted_shares: deleted.meta.changes ?? 0, deleted_orphan_files: deletedOrphans };
}

/** 清理超期的下载 / 登录日志与过期的 Turnstile 访问计数 */
export async function pruneOldLogs(
  env: Env,
  retentionDays: number
): Promise<{ deleted_download_logs: number; deleted_login_logs: number; deleted_turnstile_visits: number }> {
  const cutoff = Date.now() - Math.max(1, retentionDays) * 86_400_000;
  const dayKey = new Date().toISOString().slice(0, 10);

  const [dl, ll, tv] = await Promise.all([
    env.db.prepare("DELETE FROM download_logs WHERE created_at < ?1").bind(cutoff).run(),
    env.db.prepare("DELETE FROM login_logs WHERE created_at < ?1").bind(cutoff).run(),
    env.db.prepare("DELETE FROM turnstile_visits WHERE day < ?1").bind(dayKey).run(),
  ]);

  return {
    deleted_download_logs: dl.meta.changes ?? 0,
    deleted_login_logs: ll.meta.changes ?? 0,
    deleted_turnstile_visits: tv.meta.changes ?? 0,
  };
}

/** Cron 入口：每日自动清理（失效分享 + 超期日志），失败逐段兜底不影响其他段 */
export async function runScheduledCleanup(env: Env, ctx: ExecutionContext): Promise<void> {
  const s = await getSettings(env);
  if (!s.cronCleanupEnabled) return;
  try {
    await cleanupExpiredShares(env, ctx);
  } catch (e) {
    console.error("cron cleanup shares failed:", e);
  }
  try {
    await pruneOldLogs(env, s.logRetentionDays);
  } catch (e) {
    console.error("cron prune logs failed:", e);
  }
  // oauth_states 只插不删会无限膨胀（每次 /oauth/start 都 INSERT 一条，一次性消费只删被用到的）
  try {
    await purgeExpiredOAuthStates(env);
  } catch (e) {
    console.error("cron purge oauth states failed:", e);
  }
}
