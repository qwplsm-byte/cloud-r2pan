import { ICON_192_B64, ICON_512_B64 } from "./icons";
import type { Env } from "./types";

/**
 * PWA 静态资源：manifest / 图标 / Service Worker。
 * 项目没有静态资产通道（HTML 是文本模块导入），这些都由 Worker 动态返回。
 */

export async function serveManifest(env: Env): Promise<Response> {
  let siteTitle = "cloud-r2pan";
  try {
    const { getSettings } = await import("./settings");
    siteTitle = (await getSettings(env)).siteTitle || siteTitle;
  } catch { /* ignore */ }
  const manifest = {
    name: siteTitle,
    short_name: siteTitle,
    start_url: "/market",
    scope: "/",
    display: "standalone",
    background_color: "#0b1026",
    theme_color: "#0b1026",
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
    ],
  };
  return new Response(JSON.stringify(manifest), {
    headers: {
      "content-type": "application/manifest+json; charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
}

export function serveIcon(size: 192 | 512): Response {
  const b64 = size === 192 ? ICON_192_B64 : ICON_512_B64;
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  // 图标内容随 bundle 固定，可长缓存
  return new Response(bytes, {
    headers: { "content-type": "image/png", "cache-control": "public, max-age=604800, immutable" },
  });
}

/** 网络优先的极简 Service Worker：只兜底离线，不缓存页面/API/下载 */
export function serveServiceWorker(): Response {
  const sw = `
const CACHE = 'r2pan-static-v1';
const ASSETS = ['/icon-192.png', '/icon-512.png', '/manifest.webmanifest'];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  // API / 分享页 / 下载 / WebDAV 一律直连，绝不缓存
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/webdav') ||
      /\\/s\\/[^/]+\\/(download|verify|info)$/.test(url.pathname) || /\\/d\\/[^/]+\\/(download)?$/.test(url.pathname)) return;
  e.respondWith(
    fetch(req).then((res) => {
      if (ASSETS.includes(url.pathname) && res.ok) {
        const clone = res.clone();
        caches.open(CACHE).then((c) => c.put(req, clone));
      }
      return res;
    }).catch(() => caches.match(req))
  );
});
`;
  return new Response(sw, {
    headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "public, max-age=3600" },
  });
}
