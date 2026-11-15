// Tests for app/static/crypto.js, run with Node's built-in test runner:
//
//     node --test tests/js/
//
// No package.json, no dependencies, no build step: Node ships the same
// WebCrypto API (crypto.subtle) that browsers do, so the exact file the
// browser loads is the file under test.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

require('../../app/static/crypto.js');   // defines globalThis.SecretCrypto
const SecretCrypto = globalThis.SecretCrypto;

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'vectors', 'crypto_v1.json'), 'utf8')
);

// --- known answers (the same file tests/test_crypto_vectors.py checks) -----

for (const vector of vectors) {
  test(`matches the Python reference: ${vector.name}`, async () => {
    const result = await SecretCrypto.encryptWith(
      SecretCrypto.fromBase64Url(vector.link_secret),
      SecretCrypto.fromBase64Url(vector.iv),
      vector.plaintext
    );
    assert.equal(result.ciphertext, vector.ciphertext);
    assert.equal(result.claimToken, vector.claim_token);
    assert.equal(result.linkSecret, vector.link_secret);
    assert.equal(result.iv, vector.iv);
  });

  test(`decrypts the Python reference: ${vector.name}`, async () => {
    const plaintext = await SecretCrypto.decryptSecret(
      vector.link_secret, vector.ciphertext, vector.iv
    );
    assert.equal(plaintext, vector.plaintext);
    assert.equal(await SecretCrypto.claimTokenFor(vector.link_secret), vector.claim_token);
  });
}

// --- round trip -------------------------------------------------------------

test('a secret encrypts and decrypts back to itself', async () => {
  const secret = 'DATABASE_URL=postgres://user:p@ss/db\n🔑 ünïcödé';
  const encrypted = await SecretCrypto.encryptSecret(secret);
  const decrypted = await SecretCrypto.decryptSecret(
    encrypted.linkSecret, encrypted.ciphertext, encrypted.iv
  );
  assert.equal(decrypted, secret);
});

test('the pieces have the sizes the server checks for', async () => {
  const encrypted = await SecretCrypto.encryptSecret('hello');
  assert.equal(SecretCrypto.fromBase64Url(encrypted.linkSecret).length, 32);
  assert.equal(SecretCrypto.fromBase64Url(encrypted.claimToken).length, 32);
  assert.equal(SecretCrypto.fromBase64Url(encrypted.iv).length, 12);
  // 5 bytes of plaintext + the 16-byte GCM tag
  assert.equal(SecretCrypto.fromBase64Url(encrypted.ciphertext).length, 21);
  assert.equal(encrypted.linkSecret.length, 43);
});

test('every secret gets a fresh key and a fresh IV', async () => {
  const seen = { linkSecret: new Set(), iv: new Set(), ciphertext: new Set() };
  for (let i = 0; i < 50; i++) {
    const encrypted = await SecretCrypto.encryptSecret('same plaintext');
    seen.linkSecret.add(encrypted.linkSecret);
    seen.iv.add(encrypted.iv);
    seen.ciphertext.add(encrypted.ciphertext);
  }
  assert.equal(seen.linkSecret.size, 50);
  assert.equal(seen.iv.size, 50);
  assert.equal(seen.ciphertext.size, 50);
});

test('the claim token is not the link secret and does not appear in it', async () => {
  const encrypted = await SecretCrypto.encryptSecret('hello');
  assert.notEqual(encrypted.claimToken, encrypted.linkSecret);
  assert.equal(await SecretCrypto.claimTokenFor(encrypted.linkSecret), encrypted.claimToken);
});

// --- things that must fail --------------------------------------------------

test('the wrong key does not decrypt', async () => {
  const encrypted = await SecretCrypto.encryptSecret('hello');
  const other = await SecretCrypto.encryptSecret('hello');
  await assert.rejects(
    SecretCrypto.decryptSecret(other.linkSecret, encrypted.ciphertext, encrypted.iv)
  );
});

test('a ciphertext altered by one bit is rejected, not decrypted to garbage', async () => {
  const encrypted = await SecretCrypto.encryptSecret('transfer 100 to alice');
  const bytes = SecretCrypto.fromBase64Url(encrypted.ciphertext);
  for (const index of [0, bytes.length - 1]) {       // first data byte, last tag byte
    const tampered = bytes.slice();
    tampered[index] ^= 1;
    await assert.rejects(SecretCrypto.decryptSecret(
      encrypted.linkSecret, SecretCrypto.toBase64Url(tampered), encrypted.iv
    ));
  }
});

test('a truncated ciphertext is rejected', async () => {
  const encrypted = await SecretCrypto.encryptSecret('hello world');
  const bytes = SecretCrypto.fromBase64Url(encrypted.ciphertext);
  await assert.rejects(SecretCrypto.decryptSecret(
    encrypted.linkSecret, SecretCrypto.toBase64Url(bytes.slice(0, bytes.length - 1)), encrypted.iv
  ));
});

test('the wrong IV does not decrypt', async () => {
  const encrypted = await SecretCrypto.encryptSecret('hello');
  const otherIv = SecretCrypto.toBase64Url(new Uint8Array(12).fill(7));
  await assert.rejects(
    SecretCrypto.decryptSecret(encrypted.linkSecret, encrypted.ciphertext, otherIv)
  );
});

// --- link secret parsing ----------------------------------------------------

test('parseLinkSecret accepts exactly 32 bytes of base64url', () => {
  const valid = SecretCrypto.toBase64Url(new Uint8Array(32).fill(9));
  assert.equal(SecretCrypto.parseLinkSecret(valid).length, 32);
});

test('parseLinkSecret rejects damaged or foreign fragments', () => {
  const valid = SecretCrypto.toBase64Url(new Uint8Array(32).fill(9));
  for (const bad of [
    '',
    valid.slice(0, 20),             // link cut off in transit
    valid + 'AAAA',                 // too long
    valid.slice(0, 42) + '!',       // not base64url
    valid.slice(0, 42) + '+',       // standard base64, not the URL-safe alphabet
    'section-heading',              // an ordinary #anchor
    null,
    undefined
  ]) {
    assert.equal(SecretCrypto.parseLinkSecret(bad), null, String(bad));
  }
});

test('decrypt and claimTokenFor refuse an invalid link secret', async () => {
  await assert.rejects(SecretCrypto.claimTokenFor('too-short'));
  await assert.rejects(SecretCrypto.decryptSecret('too-short', 'AAAA', 'AAAA'));
});

// --- encoding ---------------------------------------------------------------

test('base64url round-trips every byte value and uses no padding', () => {
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  const text = SecretCrypto.toBase64Url(all);
  assert.match(text, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(SecretCrypto.fromBase64Url(text), all);
});

test('utf8Length counts bytes, not characters', () => {
  assert.equal(SecretCrypto.utf8Length('abc'), 3);
  assert.equal(SecretCrypto.utf8Length('é'), 2);
  assert.equal(SecretCrypto.utf8Length('秘'), 3);
  assert.equal(SecretCrypto.utf8Length('🔑'), 4);
});
