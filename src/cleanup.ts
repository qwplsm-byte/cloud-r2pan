import type { Env } from "./types";
import { createStorageProvider } from "./storage";
import { getSettings } from "./settings";

/**
 * 可复用的清理逻辑 —— 供两处调用：
 * 1. 管理后台手动清理 API（POST /api/admin/shares/cleanup 等）
 * 2. Cron Trigger 每日自动清理（index.ts 的 scheduled handler）
 */

/** 清理失效分享（过期 / 已撤销 / 达上限）+ 孤儿文件 + 孤儿存储对象 */
export async function cleanupExpiredShares(
  env: Env,
  ctx: ExecutionContext
): Promise<{ deleted_shares: number; deleted_orphan_files: number }> {
  const now = Date.now();
  // 1. 删除失效 shares
  const deleted = await env.db.prepare(
    "DELETE FROM shares WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads)"
  )
    .bind(now)
    .run();

  // 2. 查出孤儿 files：没有任何 share 或直链引用的文件（LEFT JOIN 反查）
  const orphans = await env.db.prepare(
    `SELECT f.id, f.key FROM files f
     LEFT JOIN shares s ON s.file_id = f.id
     LEFT JOIN direct_links d ON d.file_id = f.id
     WHERE s.id IS NULL AND d.id IS NULL`
  ).all<{ id: string; key: string }>();

  const orphanIds = (orphans.results ?? []).map((o) => o.id);
  const orphanKeys = (orphans.results ?? []).map((o) => o.key);

  // 3. 删除孤儿 files 的 DB 记录 + 关联 download_logs
  if (orphanIds.length > 0) {
    const placeholders = orphanIds.map((_, i) => `?${i + 1}`).join(", ");
    await env.db.batch([
      env.db.prepare(`DELETE FROM download_logs WHERE file_id IN (${placeholders})`).bind(...orphanIds),
      env.db.prepare(`DELETE FROM files WHERE id IN (${placeholders})`).bind(...orphanIds),
    ]);
  }

  // 4. 异步清理孤儿存储对象（不阻塞响应，批量删除可能慢）
  if (orphanKeys.length > 0) {
    ctx.waitUntil(
      (async () => {
        const st = await createStorageProvider(env, await getSettings(env));
        for (const key of orphanKeys) {
          try {
            await st.delete(key);
          } catch {
            // 删除失败不影响 DB 清理结果，静默跳过
          }
        }
      })()
    );
  }

  return { deleted_shares: deleted.meta.changes ?? 0, deleted_orphan_files: orphanIds.length };
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
}
