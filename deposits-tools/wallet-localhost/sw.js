// Service Worker: intercept POST requests to keep credentials local.
// The browser sees a successful form submission (triggering password save)
// but the secret never hits the network.
self.addEventListener('fetch', event => {
  if (event.request.method === 'POST') {
    const url = new URL(event.request.url);
    // Redirect back to the page — 303 converts POST to GET
    event.respondWith(Response.redirect(url.pathname + '#settings', 303));
  }
});
