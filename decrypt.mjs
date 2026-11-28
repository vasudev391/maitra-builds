// Decrypts a build encrypted by crypto.mjs. WebCrypto only, so the download
// page (browser) and the tests (Node) run this same code.
//
// File: "MCB1" | salt (16) | iv (12) | AES-256-GCM ciphertext + tag (16).
// Key: PBKDF2-SHA256(password, salt, ITERATIONS).

export const MAGIC = 'MCB1';
export const ITERATIONS = 310000;
export const SALT_LEN = 16;
export const IV_LEN = 12;

/** Returns the APK bytes, or throws (wrong password, damaged or foreign file). */
export async function decryptBytes(bytes, password) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const head = new TextDecoder().decode(data.subarray(0, 4));
  if (data.length < 4 + SALT_LEN + IV_LEN + 16 || head !== MAGIC) {
    throw new Error('Not an encrypted build');
  }
  const salt = data.subarray(4, 4 + SALT_LEN);
  const iv = data.subarray(4 + SALT_LEN, 4 + SALT_LEN + IV_LEN);
  const body = data.subarray(4 + SALT_LEN + IV_LEN);
  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, body));
}
