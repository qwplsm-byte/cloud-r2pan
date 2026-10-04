import type { Env } from "./types";
import { getSettings } from "./settings";
import { decryptSecret } from "./crypto";

/**
 * 事件通知 —— Webhook（POST JSON）+ Telegram Bot 双渠道。
 * 全部在 ctx.waitUntil / 后台路径中调用，失败静默，绝不影响主流程。
 */

export type NotifyEvent = "download" | "quota" | "login";

/** isolate 内节流：同一 key 60 秒内只发一次（防下载刷屏 / 防爆破告警刷屏） */
const _lastNotifyAt = new Map<string, number>();
const THROTTLE_MS = 60_000;

export async function notifyEvent(
  env: Env,
  event: NotifyEvent,
  text: string,
  throttleKey?: string
): Promise<void> {
  try {
    const s = await getSettings(env);
    const enabled =
      (event === "download" && s.notifyEventDownload) ||
      (event === "quota" && s.notifyEventQuota) ||
      (event === "login" && s.notifyEventLogin);
    if (!enabled) return;

    if (throttleKey) {
      const now = Date.now();
      const last = _lastNotifyAt.get(throttleKey) ?? 0;
      if (now - last < THROTTLE_MS) return;
      _lastNotifyAt.set(throttleKey, now);
      // 防内存膨胀：超过 500 条时清空重建（低频路径，简单粗暴即可）
      if (_lastNotifyAt.size > 500) _lastNotifyAt.clear();
    }

    const site = s.siteTitle || "cloud-r2pan";
    const full = `[${site}] ${text}`;
    const jobs: Promise<void>[] = [];

    const webhookUrl = s.notifyWebhookCipher ? await decryptSecret(s.notifyWebhookCipher, env.admin) : null;
    if (webhookUrl) {
      jobs.push(
        fetch(webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ event, site_title: site, text: full, ts: Date.now() }),
        }).then((r) => {
          if (!r.ok) console.warn(`[notify] webhook ${r.status}`);
        })
      );
    }

    const tgToken = s.notifyTgCipher ? await decryptSecret(s.notifyTgCipher, env.admin) : null;
    if (tgToken && s.notifyTgChatId) {
      jobs.push(
        fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chat_id: s.notifyTgChatId, text: full }),
        }).then((r) => {
          if (!r.ok) console.warn(`[notify] telegram ${r.status}`);
        })
      );
    }

    await Promise.allSettled(jobs);
  } catch {
    // 通知失败不影响任何主流程
  }
}

/** 发送测试通知（设置页按钮调用）。返回各渠道是否成功。 */
export async function sendTestNotification(env: Env): Promise<{ webhook: boolean; telegram: boolean }> {
  const s = await getSettings(env);
  const text = `[${s.siteTitle || "cloud-r2pan"}] ✅ 测试通知 Test notification`;
  const result = { webhook: false, telegram: false };
  const webhookUrl = s.notifyWebhookCipher ? await decryptSecret(s.notifyWebhookCipher, env.admin) : null;
  if (webhookUrl) {
    result.webhook = await fetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: "test", site_title: s.siteTitle, text, ts: Date.now() }),
    }).then((r) => r.ok).catch(() => false);
  }
  const tgToken = s.notifyTgCipher ? await decryptSecret(s.notifyTgCipher, env.admin) : null;
  if (tgToken && s.notifyTgChatId) {
    result.telegram = await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: s.notifyTgChatId, text }),
    }).then((r) => r.ok).catch(() => false);
  }
  return result;
}
