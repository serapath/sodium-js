// browser.js (what browsers get) against sodium-native (what node and bare get), run in node
const test = require('brittle')
const crypto = require('crypto')
const browser = require('../browser.js')
const native = require('sodium-native')

/******************************************************************************
  before sodium.ready, libsodium.js isnt there yet
******************************************************************************/
test('before sodium.ready noclamp throws a clear error and the rest runs on sodium-javascript', function (t) {
  const q = new Uint8Array(32)
  t.exception(() => browser.crypto_scalarmult_ed25519_noclamp(q, random(32), public_key()), /await sodium.ready/)
  const message = random(100)
  const seed = random(32)
  t.alike(hash(browser, message), hash(native, message), 'generichash')
  t.alike(keypair(browser, seed), keypair(native, seed), 'seed keypair')
  const { sk } = keypair(native, seed)
  t.alike(sign(browser, message, sk), sign(native, message, sk), 'sign')
})

/******************************************************************************
  crypto_scalarmult_ed25519_noclamp
******************************************************************************/
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
  generichash and ed25519 from libsodium.js, after sodium.ready
******************************************************************************/
test('generichash matches sodium-native, 16 / 32 / 64 bytes, with and without a key, empty input', async function (t) {
  await browser.ready
  let same = 0
  let runs = 0
  for (const length of [16, 32, 64]) {
    for (const key of [null, random(32)]) {
      for (const message of [Buffer.alloc(0), ...Array.from({ length: 100 }, () => random(Math.floor(Math.random() * 2000)))]) {
        runs++
        if (Buffer.compare(hash(browser, message, length, key), hash(native, message, length, key)) === 0) same++
      }
    }
  }
  t.is(same, runs)
})

test('generichash_batch matches sodium-native, with and without a key', async function (t) {
  await browser.ready
  let same = 0
  for (let i = 0; i < 200; i++) {
    const inputs = Array.from({ length: 1 + (i % 5) }, () => random(Math.floor(Math.random() * 300)))
    const key = i % 2 ? random(32) : undefined
    const a = Buffer.alloc(32)
    const b = Buffer.alloc(32)
    browser.crypto_generichash_batch(a, inputs, key)
    native.crypto_generichash_batch(b, inputs, key)
    if (Buffer.compare(a, b) === 0) same++
  }
  t.is(same, 200)
})

test('seed keypair and sign match sodium-native, 200 random seeds and messages', async function (t) {
  await browser.ready
  let same = 0
  for (let i = 0; i < 200; i++) {
    const seed = random(32)
    const message = random(Math.floor(Math.random() * 2000))
    const a = keypair(browser, seed)
    const b = keypair(native, seed)
    if (Buffer.compare(a.pk, b.pk) === 0 && Buffer.compare(a.sk, b.sk) === 0 &&
      Buffer.compare(sign(browser, message, a.sk), sign(native, message, b.sk)) === 0) same++
  }
  t.is(same, 200)
})

test('a random keypair from libsodium.js works with sodium-native', async function (t) {
  await browser.ready
  const pk = Buffer.alloc(32)
  const sk = Buffer.alloc(64)
  browser.crypto_sign_keypair(pk, sk)
  const from_sk = Buffer.alloc(32)
  native.crypto_sign_ed25519_sk_to_pk(from_sk, sk)
  t.alike(from_sk, pk, 'public key belongs to the secret key')
  const message = random(100)
  t.ok(native.crypto_sign_verify_detached(sign(browser, message, sk), message, pk), 'sodium-native verifies its signature')
})

test('verify gives the same answer as sodium-native, also for a wrong signature, a bad public key and wrong lengths', async function (t) {
  await browser.ready
  const { pk, sk } = keypair(native, random(32))
  const message = random(100)
  const sig = sign(native, message, sk)
  const flipped = Buffer.from(sig)
  flipped[0] ^= 1
  const cases = {
    valid: [sig, message, pk],
    'wrong signature': [flipped, message, pk],
    'other message': [sig, random(100), pk],
    'random public key': [sig, message, random(32)],
    'zero public key': [sig, message, Buffer.alloc(32)],
    'short signature': [sig.subarray(0, 63), message, pk],
    'short public key': [sig, message, pk.subarray(0, 31)]
  }
  for (const [name, args] of Object.entries(cases)) {
    t.is(outcome(() => browser.crypto_sign_verify_detached(...args)), outcome(() => native.crypto_sign_verify_detached(...args)), name)
  }
})

/******************************************************************************
  extension_pbkdf2_sha512_async
******************************************************************************/
test('pbkdf2 (web crypto) matches sodium-native and node crypto', async function (t) {
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
    t.alike(nat, want, 'sodium-native = node crypto, keylen ' + keylen)
    t.alike(Buffer.from(web), want, 'web crypto, keylen ' + keylen)
  }
})

test('pbkdf2 throws a clear error without web crypto (a page that isnt https or localhost)', async function (t) {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })
  try {
    await t.exception(browser.extension_pbkdf2_sha512_async(new Uint8Array(64), random(10), random(8), 1, 64), /web crypto/)
  } finally {
    Object.defineProperty(globalThis, 'crypto', original)
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

function hash (sodium, message, length = 32, key) {
  const out = Buffer.alloc(length)
  sodium.crypto_generichash(out, message, key)
  return out
}

function keypair (sodium, seed) {
  const pk = Buffer.alloc(32)
  const sk = Buffer.alloc(64)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return { pk, sk }
}

function sign (sodium, message, sk) {
  const sig = Buffer.alloc(64)
  sodium.crypto_sign_detached(sig, message, sk)
  return sig
}

// what a call gives back, or 'threw', so two libraries can be compared on bad input too
function outcome (fn) {
  try { return fn() } catch { return 'threw' }
}
