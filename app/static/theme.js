// Wires up the theme toggle button. The initial theme itself is set by
// theme-init.js, which <head> loads without `defer` (so before this file) to
// avoid a flash of the wrong theme on page load.
(function () {
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('theme', theme);
    } catch (_err) { /* storage blocked: the choice just won't persist */ }
  }

  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.addEventListener('click', function () {
      setTheme(currentTheme() === 'light' ? 'dark' : 'light');
    });
  }
})();
