import type { Env } from "./types";

/**
 * WebAuthn/Passkey 辅助 —— challenge 存取与编码工具。
 * 验证逻辑使用 @simplewebauthn/server（在 admin.ts 内动态 import）。
 */

/** 保存一次性 challenge（同 purpose 只保留最新一条，2 分钟过期） */
export async function saveChallenge(env: Env, challenge: string, purpose: "register" | "auth"): Promise<void> {
  await env.db.batch([
    env.db.prepare("DELETE FROM webauthn_challenges WHERE purpose = ?1").bind(purpose),
    env.db.prepare("INSERT INTO webauthn_challenges(challenge, purpose, expires_at) VALUES(?1, ?2, ?3)")
      .bind(challenge, purpose, Date.now() + 120_000),
  ]);
}

/** 取出并删除 challenge（一次性使用），过期或不存在返回 null */
export async function takeChallenge(env: Env, purpose: "register" | "auth"): Promise<string | null> {
  const row = await env.db.prepare(
    "SELECT challenge FROM webauthn_challenges WHERE purpose = ?1 AND expires_at > ?2"
  ).bind(purpose, Date.now()).first<{ challenge: string }>();
  if (!row) return null;
  await env.db.prepare("DELETE FROM webauthn_challenges WHERE purpose = ?1").bind(purpose).run();
  return row.challenge ?? null;
}

/** 是否已注册过任意 Passkey（登录页决定是否显示登录按钮） */
export async function hasCredentials(env: Env): Promise<boolean> {
  const row = await env.db.prepare("SELECT COUNT(*) AS c FROM webauthn_credentials").first<{ c: number }>();
  return (row?.c ?? 0) > 0;
}

export function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
