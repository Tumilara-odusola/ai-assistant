// Basic service worker: enables installability and gives a clean offline
// fallback for navigations. Deliberately does NOT cache dashboard pages or
// any other dynamic, per-request content — those reflect live bookings and
// orders, and serving a stale cached copy while offline would be worse than
// a clear "you're offline" message.
const CACHE_NAME = 'autumn-static-v1';
const PRECACHE_URLS = [
  '/manifest.json',
  '/offline.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Network-first for page navigations, falling back to the cached offline
  // page only when the network is unreachable.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/offline.html'))
    );
    return;
  }

  // Cache-first for the static assets we precached; everything else
  // (API-ish routes, dynamic dashboard fragments) just goes to the network.
  if (PRECACHE_URLS.includes(new URL(request.url).pathname)) {
    event.respondWith(
      caches.match(request).then((cached) => cached || fetch(request))
    );
  }
});
