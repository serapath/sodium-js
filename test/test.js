// browser.js (what browsers get) against sodium-native (what node and bare get), run in node
const test = require('brittle')
const crypto = require('crypto')
const browser = require('../browser.js')
const native = require('sodium-native')
const { pbkdf2_js } = require('../lib/pbkdf2')

/******************************************************************************
  crypto_scalarmult_ed25519_noclamp
******************************************************************************/
test('noclamp throws a clear error before sodium.ready', function (t) {
  const q = new Uint8Array(32)
  t.exception(() => browser.crypto_scalarmult_ed25519_noclamp(q, random(32), public_key()), /await sodium.ready/)
})

test('noclamp gives the same point as sodium-native, 1000 random scalars and points', async function (t) {
  await browser.ready
  let same = 0
  for (let i = 0; i < 1000; i++) {
    const n = random(32)
    const p = public_key()
    const a = new Uint8Array(32)
    const b = Buffer.alloc(32)
    browser.crypto_scalarmult_ed25519_noclamp(a, n, p)
    native.crypto_scalarmult_ed25519_noclamp(b, n, p)
    if (Buffer.compare(Buffer.from(a), b) === 0) same++
  }
  t.is(same, 1000)
})

test('noclamp refuses the identity point and a small order point, like sodium-native', async function (t) {
  await browser.ready
  const identity = Buffer.alloc(32)
  identity[0] = 1
  const small_order = Buffer.alloc(32) // y = 0, a point of order 4
  for (const p of [identity, small_order]) {
    t.exception(() => browser.crypto_scalarmult_ed25519_noclamp(new Uint8Array(32), random(32), p))
    t.exception(() => native.crypto_scalarmult_ed25519_noclamp(Buffer.alloc(32), random(32), p))
  }
})

/******************************************************************************
  extension_pbkdf2_sha512_async
******************************************************************************/
test('pbkdf2 (web crypto and the js fallback) matches sodium-native and node crypto', async function (t) {
  const cases = [
    { password: Buffer.from('abandon '.repeat(23) + 'art'), salt: Buffer.from('mnemonic'), iterations: 2048, keylen: 64 }, // bip39
    { password: random(200), salt: random(16), iterations: 3, keylen: 100 }, // long password, 2 blocks
    { password: random(5), salt: random(1), iterations: 1, keylen: 10 }
  ]
  for (const { password, salt, iterations, keylen } of cases) {
    const want = crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha512')
    const nat = Buffer.alloc(keylen)
    await native.extension_pbkdf2_sha512_async(nat, password, salt, iterations, keylen)
    const web = await browser.extension_pbkdf2_sha512_async(new Uint8Array(keylen), password, salt, iterations, keylen)
    const js = pbkdf2_js(new Uint8Array(keylen), password, salt, iterations, keylen)
    t.alike(nat, want, 'sodium-native = node crypto, keylen ' + keylen)
    t.alike(Buffer.from(web), want, 'web crypto path, keylen ' + keylen)
    t.alike(Buffer.from(js), want, 'js fallback, keylen ' + keylen)
  }
})

/******************************************************************************
  xchacha20poly1305 and kx (from @geut/sodium-javascript-plus)
******************************************************************************/
test('xchacha20poly1305 encrypts and decrypts across browser.js and sodium-native', function (t) {
  const key = random(32)
  const nonce = random(24)
  const ad = random(12)
  const message = random(100)
  const cipher = Buffer.alloc(message.length + 16)
  browser.crypto_aead_xchacha20poly1305_ietf_encrypt(cipher, message, ad, null, nonce, key)
  const expected = Buffer.alloc(message.length + 16)
  native.crypto_aead_xchacha20poly1305_ietf_encrypt(expected, message, ad, null, nonce, key)
  t.alike(cipher, expected)
  const plain = Buffer.alloc(message.length)
  native.crypto_aead_xchacha20poly1305_ietf_decrypt(plain, null, cipher, ad, nonce, key)
  t.alike(plain, message)
})

test('kx session keys match sodium-native', function (t) {
  const client = { pk: Buffer.alloc(32), sk: Buffer.alloc(32) }
  const server = { pk: Buffer.alloc(32), sk: Buffer.alloc(32) }
  native.crypto_kx_keypair(client.pk, client.sk)
  native.crypto_kx_keypair(server.pk, server.sk)
  const a = [Buffer.alloc(32), Buffer.alloc(32)]
  const b = [Buffer.alloc(32), Buffer.alloc(32)]
  browser.crypto_kx_client_session_keys(a[0], a[1], client.pk, client.sk, server.pk)
  native.crypto_kx_client_session_keys(b[0], b[1], client.pk, client.sk, server.pk)
  t.alike(a, b)
})

function random (n) { return crypto.randomBytes(n) }
function public_key () {
  const pk = Buffer.alloc(32)
  native.crypto_sign_keypair(pk, Buffer.alloc(64))
  return pk
}
