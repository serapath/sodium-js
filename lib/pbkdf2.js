// pbkdf2 with hmac-sha512, the same as sodium-native's extension_pbkdf2_sha512_async (bip39-mnemonic makes seeds with it)
// only the browsers own web crypto, no pbkdf2 of our own. web crypto needs a secure context (https or localhost)
module.exports = { extension_pbkdf2_sha512_async }

async function extension_pbkdf2_sha512_async (out, password, salt, iterations, keylen) {
  if (out.length < keylen) throw new Error('out is shorter than keylen')
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (!subtle) throw new Error('pbkdf2 needs web crypto (crypto.subtle), which only exists on https or localhost')
  const key = await subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-512' }, key, keylen * 8)
  out.set(new Uint8Array(bits))
  return out
}
