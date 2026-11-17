// The create page: encrypt in the browser, send only ciphertext, then build
// the share link here — its second half is the key, which the server never
// receives and so could not put in a link for us.
(function () {
  'use strict';

  var form = document.getElementById('create-form');
  var payload = document.getElementById('payload');
  var allowedEmails = document.getElementById('allowed_emails');
  var submitButton = document.getElementById('create-btn');
  var errorBox = document.getElementById('form-error');
  var createView = document.getElementById('create-view');
  var resultView = document.getElementById('result-view');
  var shareUrl = document.getElementById('share-url');
  var copyButton = document.getElementById('copy-btn');
  var maxBytes = parseInt(form.dataset.maxBytes, 10);

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  // WebCrypto only exists on HTTPS pages (and on http://localhost). Without
  // it there is no safe way to continue: sending the secret unencrypted is
  // exactly what this app exists to avoid, so there is no fallback.
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    showError('This page needs a secure (HTTPS) connection to encrypt your secret.');
    submitButton.disabled = true;
    return;
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    errorBox.hidden = true;

    var text = payload.value;
    if (!text.trim()) {
      showError('Secret cannot be empty.');
      return;
    }
    if (SecretCrypto.utf8Length(text) > maxBytes) {
      showError('Secret is too large (limit ' + maxBytes.toLocaleString() + ' bytes).');
      return;
    }

    submitButton.disabled = true;
    try {
      var encrypted = await SecretCrypto.encryptSecret(text);
      var response = await fetch('/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Note what is absent: the plaintext and encrypted.linkSecret.
        body: JSON.stringify({
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          claim_token: encrypted.claimToken,
          allowed_emails: allowedEmails.value
        })
      });
      var body = await response.json().catch(function () { return {}; });
      if (!response.ok) {
        showError(typeof body.detail === 'string' ? body.detail : 'Could not create the link.');
        return;
      }

      // The key goes after "#". That part of a URL stays in the browser: it
      // is not sent to the server when the recipient opens the link.
      shareUrl.textContent =
        window.location.origin + '/secret/' + body.id + '#' + encrypted.linkSecret;
      payload.value = '';
      createView.hidden = true;
      resultView.hidden = false;
    } catch (_err) {
      showError('Could not create the link. Check your connection and try again.');
    } finally {
      submitButton.disabled = false;
    }
  });

  copyButton.addEventListener('click', function () {
    navigator.clipboard.writeText(shareUrl.textContent).then(function () {
      copyButton.textContent = 'Copied!';
      copyButton.classList.add('copied');
      setTimeout(function () {
        copyButton.textContent = 'Copy';
        copyButton.classList.remove('copied');
      }, 2000);
    });
  });
})();
