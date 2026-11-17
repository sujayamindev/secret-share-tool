// Sets the colour theme before the page is painted, to avoid a flash of the
// wrong one. Loaded from <head> WITHOUT `defer`, so the browser runs it before
// rendering the body.
//
// This used to be an inline <script> in every template. It is a file now
// because the Content-Security-Policy forbids inline script entirely — that
// policy is what stops injected script from reading a decryption key.
(function () {
  var stored = null;
  try {
    stored = localStorage.getItem('theme');
  } catch (_err) { /* storage blocked: fall back to the system preference */ }
  var theme = stored === 'light' || stored === 'dark'
    ? stored
    : (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-theme', theme);
})();
