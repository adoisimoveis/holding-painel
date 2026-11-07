/* Guarda só a casca do app (HTML, CSS, JS, ícones) para abrir rápido.
   Nunca guarda respostas do GitHub: os dados são sempre buscados na hora. */
const VERSAO = "painel-v1";
const CASCA = ["./", "index.html", "app.css", "app.js", "manifest.webmanifest", "icone.svg", "icone-192.png", "icone-512.png"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(VERSAO).then((c) => c.addAll(CASCA))); self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSAO).map((k) => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || e.request.method !== "GET") return; // GitHub e envios: direto na rede
  e.respondWith(fetch(e.request).then((r) => { const copia = r.clone(); caches.open(VERSAO).then((c) => c.put(e.request, copia)); return r; })
    .catch(() => caches.match(e.request)));
});
