// All of the app's cryptography. Everything here runs in the browser; the
// server never executes this file and never sees a key.
//
// How a secret is protected:
//
//   link secret   32 random bytes. Lives only in the share link, after the
//                 "#". Browsers do not include that part of a URL in requests,
//                 so the server never receives it.
//
//   From the link secret, HKDF-SHA-256 derives two independent values:
//
//   encryption key  AES-256-GCM key. Encrypts and decrypts the secret.
//                   Never leaves the browser.
//   claim token     Sent to the server. Proves "I hold the full link" when
//                   collecting the ciphertext, without revealing the key:
//                   HKDF is one-way, and its outputs for different `info`
//                   labels tell you nothing about each other.
//
// Why AES-GCM: it is authenticated encryption. Decryption checks a tag, so a
// ciphertext that was altered in storage or transit fails loudly instead of
// decrypting to something subtly wrong.
//
// Why a random IV is safe here: GCM is broken if one key is ever used with
// the same IV twice. Each link secret (and so each key) encrypts exactly one
// message, ever, so a repeat is impossible by construction. The IV is still
// random and stored with the ciphertext, because that is the standard form.
//
// No library: WebCrypto (crypto.subtle) is built into browsers and into
// Node, which is how tests/js/ runs this same file without a build step.
(function (root) {
  'use strict';

  var subtle = root.crypto.subtle;
  var encoder = new TextEncoder();

  var KEY_BYTES = 32;
  var IV_BYTES = 12;
  // The labels that make the two derived values different from each other.
  // "v1" leaves room to change the scheme later without ambiguity.
  var INFO_ENCRYPTION = encoder.encode('secret-share/v1/enc');
  var INFO_CLAIM = encoder.encode('secret-share/v1/claim');
  // HKDF's salt strengthens weak input. The input here is already 256 bits
  // of uniform randomness, so a fixed all-zero salt (RFC 5869's default) is
  // the correct choice, and it keeps the link self-contained.
  var HKDF_SALT = new Uint8Array(32);

  function toBase64Url(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromBase64Url(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) {
      throw new Error('Not base64url');
    }
    var base64 = text.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Returns the 32 bytes of a link secret, or null if the text is not one
  // (wrong length, wrong characters — e.g. a link that was cut off in transit).
  function parseLinkSecret(text) {
    try {
      var bytes = fromBase64Url(text);
      return bytes.length === KEY_BYTES ? bytes : null;
    } catch (_err) {
      return null;
    }
  }

  async function deriveKeys(linkSecret) {
    var base = await subtle.importKey('raw', linkSecret, 'HKDF', false, ['deriveKey', 'deriveBits']);
    // extractable=false: once imported, script can use this key but cannot
    // read its bytes back out.
    var encryptionKey = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: INFO_ENCRYPTION },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    var claimBits = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: INFO_CLAIM },
      base,
      256
    );
    return { encryptionKey: encryptionKey, claimToken: new Uint8Array(claimBits) };
  }

  // Encrypt with a given link secret and IV. Separate from encryptSecret so
  // the tests can feed fixed inputs and compare against known answers.
  async function encryptWith(linkSecret, iv, plaintext) {
    var keys = await deriveKeys(linkSecret);
    var ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv: iv },   // tag length defaults to 128 bits
      keys.encryptionKey,
      encoder.encode(plaintext)
    );
    return {
      linkSecret: toBase64Url(linkSecret),
      ciphertext: toBase64Url(new Uint8Array(ciphertext)),   // includes the tag
      iv: toBase64Url(iv),
      claimToken: toBase64Url(keys.claimToken)
    };
  }

  // What the create page calls: fresh randomness for both the secret and IV.
  function encryptSecret(plaintext) {
    var linkSecret = root.crypto.getRandomValues(new Uint8Array(KEY_BYTES));
    var iv = root.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    return encryptWith(linkSecret, iv, plaintext);
  }

  async function claimTokenFor(linkSecretText) {
    var linkSecret = parseLinkSecret(linkSecretText);
    if (!linkSecret) {
      throw new Error('Invalid link secret');
    }
    var keys = await deriveKeys(linkSecret);
    return toBase64Url(keys.claimToken);
  }

  // Throws if the key is wrong or the ciphertext was modified: GCM's tag
  // check fails and WebCrypto rejects, rather than returning garbage.
  async function decryptSecret(linkSecretText, ciphertextText, ivText) {
    var linkSecret = parseLinkSecret(linkSecretText);
    if (!linkSecret) {
      throw new Error('Invalid link secret');
    }
    var keys = await deriveKeys(linkSecret);
    var plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64Url(ivText) },
      keys.encryptionKey,
      fromBase64Url(ciphertextText)
    );
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  }

  function utf8Length(text) {
    return encoder.encode(text).length;
  }

  root.SecretCrypto = {
    encryptSecret: encryptSecret,
    encryptWith: encryptWith,
    decryptSecret: decryptSecret,
    claimTokenFor: claimTokenFor,
    parseLinkSecret: parseLinkSecret,
    toBase64Url: toBase64Url,
    fromBase64Url: fromBase64Url,
    utf8Length: utf8Length
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
