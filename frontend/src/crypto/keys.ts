import { b64UrlDecode, b64UrlEncode, utf8ToBytes } from "./base64";

const PBKDF2_ITERATIONS = 200_000;

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return new Uint8Array(arr);
}

async function deriveWrappingKey(password: string, salt: Uint8Array) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(utf8ToBytes(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function generateKeypair() {
  const kp = await crypto.subtle.generateKey(
    {
      name: "X25519",
    },
    true,
    ["deriveBits"]
  );

  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const privateRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

  return {
    publicKeyCrypto: kp.publicKey,
    privateKeyCrypto: kp.privateKey,
    publicKeyB64: b64UrlEncode(publicRaw),
    privateKeyPkcs8B64: b64UrlEncode(privateRaw),
  };
}

export async function encryptPrivateKey(privateKeyPkcs8B64: string, password: string) {
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const wrappingKey = await deriveWrappingKey(password, salt);
  const plaintext = b64UrlDecode(privateKeyPkcs8B64);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(nonce) },
      wrappingKey,
      new Uint8Array(plaintext)
    )
  );

  return JSON.stringify({
    ciphertext: b64UrlEncode(ciphertext),
    salt: b64UrlEncode(salt),
    nonce: b64UrlEncode(nonce),
  });
}

export async function decryptPrivateKey(encryptedPayload: string, password: string) {
  const parsed = JSON.parse(encryptedPayload);
  const salt = b64UrlDecode(parsed.salt);
  const nonce = b64UrlDecode(parsed.nonce);
  const ciphertext = b64UrlDecode(parsed.ciphertext);

  const wrappingKey = await deriveWrappingKey(password, salt);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(nonce) },
      wrappingKey,
      new Uint8Array(ciphertext)
    )
  );

  return b64UrlEncode(plaintext);
}

export async function importRecipientPublicKey(publicKeyB64: string) {
  return crypto.subtle.importKey(
    "raw",
    new Uint8Array(b64UrlDecode(publicKeyB64)),
    { name: "X25519" },
    true,
    []
  );
}

export async function importPrivateKeyFromPkcs8B64(privateKeyPkcs8B64: string) {
  return crypto.subtle.importKey(
    "pkcs8",
    new Uint8Array(b64UrlDecode(privateKeyPkcs8B64)),
    { name: "X25519" },
    true,
    ["deriveBits"]
  );
}