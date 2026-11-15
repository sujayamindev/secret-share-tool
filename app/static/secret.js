// The secret page. Order matters in this file: the first thing it does is
// get the key out of the address bar.
(function () {
  'use strict';

  var main = document.getElementById('secret-main');
  var secretId = main.dataset.secretId;
  var authenticated = main.dataset.authenticated === 'true';
  var storageKey = 'link-secret:' + secretId;

  // --- Step 1: move the key from the URL into sessionStorage -------------
  //
  // The key arrives as the URL fragment (after "#"). It must not still be in
  // the URL when the user leaves for the sign-in page: browsers carry a
  // fragment along through redirects, which would show the key to the
  // identity provider's page.
  //
  // sessionStorage is the right holding place because it is (a) never sent
  // in any request, (b) private to this site, and (c) private to this tab
  // and gone when the tab closes. It survives the trip to the sign-in page
  // and back because that happens in the same tab.
  var fragment = window.location.hash.slice(1);
  if (fragment) {
    if (SecretCrypto.parseLinkSecret(fragment)) {
      try {
        sessionStorage.setItem(storageKey, fragment);
      } catch (_err) {
        // Storage unavailable (some private modes). The key is then lost on
        // navigation; the page will say the link is incomplete after sign-in.
      }
    }
    // replaceState rewrites the current history entry instead of adding one,
    // so the Back button does not lead to a URL with the key in it either.
    history.replaceState(null, '', window.location.pathname);
  }

  function storedLinkSecret() {
    try {
      return sessionStorage.getItem(storageKey);
    } catch (_err) {
      return null;
    }
  }

  function forgetLinkSecret() {
    try {
      sessionStorage.removeItem(storageKey);
    } catch (_err) { /* nothing to forget */ }
  }

  // --- Step 2: show the right view ---------------------------------------
  var views = ['view-missing-key', 'view-sign-in', 'view-reveal', 'view-secret', 'view-gone'];

  function show(viewId) {
    views.forEach(function (id) {
      document.getElementById(id).hidden = id !== viewId;
    });
  }

  var linkSecret = storedLinkSecret();
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    show('view-missing-key');
    document.getElementById('missing-key-text').textContent =
      'This page needs a secure (HTTPS) connection to decrypt the secret.';
  } else if (!linkSecret) {
    // No key: the Reveal button is never offered, so nothing can be claimed
    // and the secret is untouched. Reopening the full link works.
    show('view-missing-key');
  } else if (!authenticated) {
    show('view-sign-in');
  } else {
    show('view-reveal');
  }

  // --- Step 3: reveal ------------------------------------------------------
  var revealButton = document.getElementById('reveal-btn');
  var revealError = document.getElementById('reveal-error');

  revealButton.addEventListener('click', async function () {
    revealButton.disabled = true;
    revealError.hidden = true;
    try {
      var claimToken = await SecretCrypto.claimTokenFor(linkSecret);
      var response = await fetch('/api/secrets/' + secretId + '/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim_token: claimToken })
      });

      if (response.status === 401) {
        // Session expired since the page loaded. Reload: the server will
        // render the sign-in view, and the key is still in sessionStorage.
        window.location.reload();
        return;
      }
      if (!response.ok) {
        // Deliberately one message. The server gives the same answer for
        // "used", "expired", "not for this account" and "never existed".
        show('view-gone');
        return;
      }

      var body = await response.json();
      var plaintext = await SecretCrypto.decryptSecret(linkSecret, body.ciphertext, body.iv);
      // The server has already deleted its copy; now drop ours.
      forgetLinkSecret();
      // textContent, never innerHTML: the secret is shown as text even if it
      // happens to contain HTML.
      document.getElementById('secret-text').textContent = plaintext;
      show('view-secret');
    } catch (_err) {
      revealError.textContent = 'Could not reveal the secret. Check your connection and try again.';
      revealError.hidden = false;
      revealButton.disabled = false;
    }
  });

  // --- Copy and sign out ---------------------------------------------------
  var copyButton = document.getElementById('copy-btn');
  copyButton.addEventListener('click', function () {
    var text = document.getElementById('secret-text').textContent;
    navigator.clipboard.writeText(text).then(function () {
      copyButton.textContent = 'Copied!';
      copyButton.classList.add('copied');
      setTimeout(function () {
        copyButton.textContent = 'Copy';
        copyButton.classList.remove('copied');
      }, 2000);
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll('.sign-out'), function (button) {
    button.addEventListener('click', async function () {
      button.disabled = true;
      var target = '/';
      try {
        var response = await fetch('/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}'
        });
        var body = await response.json();
        if (typeof body.redirect === 'string') {
          target = body.redirect;
        }
      } catch (_err) { /* fall through to the home page */ }
      window.location.assign(target);
    });
  });
})();
