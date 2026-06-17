// Service Worker: intercept POST requests to keep credentials local.
// The browser sees a successful form submission (triggering password save)
// but the secret never hits the network.
const TABS = ['wallet', 'deposits', 'discover', 'transfer', 'ledgers', 'settings'];

self.addEventListener('fetch', event => {
  if (event.request.method === 'POST') {
    const url = new URL(event.request.url);
    // Redirect back to the page — 303 converts POST to GET. The page passes
    // the tab to return to as ?tab=… (the URL fragment isn't sent with a
    // POST). Default to the Wallet home so a first-run save doesn't strand a
    // new user on Settings. Validate against the known tabs before echoing.
    const want = url.searchParams.get('tab');
    const tab = TABS.includes(want) ? want : 'wallet';
    event.respondWith(Response.redirect(url.pathname + '#' + tab, 303));
  }
});
