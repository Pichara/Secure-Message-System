import { b64UrlDecode, b64UrlEncode, bytesToUtf8, utf8ToBytes } from "./base64";
import { importPrivateKeyFromPkcs8B64, importRecipientPublicKey } from "./keys";

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

async function deriveAesKey(sharedBits: ArrayBuffer, salt: Uint8Array) {
  const sharedKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: utf8ToBytes("secure-message-ecdh") as BufferSource,
    },
    sharedKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveWrappingKey(sharedBits: ArrayBuffer, salt: Uint8Array) {
  const sharedKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: utf8ToBytes("secure-message-key-wrap-v2") as BufferSource,
    },
    sharedKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessage(plaintext: string, recipientPublicKeyB64: string) {
  const recipientPublicKey = await importRecipientPublicKey(recipientPublicKeyB64);

  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));

  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: recipientPublicKey,
    },
    eph.privateKey,
    256
  );

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const aesKey = await deriveAesKey(sharedBits, salt);

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      aesKey,
      new Uint8Array(utf8ToBytes(plaintext))
    )
  );

  const encrypted_key = JSON.stringify({
    epk: b64UrlEncode(ephPublicRaw),
    salt: b64UrlEncode(salt),
  });

  return {
    encrypted_key,
    ciphertext: b64UrlEncode(ciphertext),
    iv: b64UrlEncode(iv),
  };
}

export async function encryptMessageForRecipients(
  plaintext: string,
  recipients: Array<{ username: string; publicKey: string }>
) {
  const uniqueRecipients = recipients.filter(
    (recipient, index, all) =>
      recipient.username &&
      recipient.publicKey &&
      all.findIndex((item) => item.username === recipient.username) === index
  );

  if (uniqueRecipients.length === 0) {
    throw new Error("No recipients available for encryption");
  }

  const messageKey = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
  const rawMessageKey = new Uint8Array(await crypto.subtle.exportKey("raw", messageKey));
  const iv = randomBytes(12);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      messageKey,
      new Uint8Array(utf8ToBytes(plaintext))
    )
  );

  const copies: Record<string, { epk: string; salt: string; iv: string; key: string }> = {};

  for (const recipient of uniqueRecipients) {
    const recipientPublicKey = await importRecipientPublicKey(recipient.publicKey);
    const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const ephPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
    const sharedBits = await crypto.subtle.deriveBits(
      {
        name: "X25519",
        public: recipientPublicKey,
      },
      eph.privateKey,
      256
    );

    const salt = randomBytes(16);
    const keyIv = randomBytes(12);
    const wrappingKey = await deriveWrappingKey(sharedBits, salt);
    const wrappedKey = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: new Uint8Array(keyIv) },
        wrappingKey,
        new Uint8Array(rawMessageKey)
      )
    );

    copies[recipient.username] = {
      epk: b64UrlEncode(ephPublicRaw),
      salt: b64UrlEncode(salt),
      iv: b64UrlEncode(keyIv),
      key: b64UrlEncode(wrappedKey),
    };
  }

  return {
    encrypted_key: JSON.stringify({ v: 2, copies }),
    ciphertext: b64UrlEncode(ciphertext),
    iv: b64UrlEncode(iv),
  };
}

export async function decryptMessage(
  ciphertextB64: string,
  ivB64: string,
  encryptedKeyPayload: string,
  privateKeyPkcs8B64: string,
  username?: string
) {
  const parsed = JSON.parse(encryptedKeyPayload);

  if (parsed.v === 2 && parsed.copies) {
    const copy = username ? parsed.copies[username] : Object.values(parsed.copies)[0];
    if (!copy) {
      throw new Error("No encrypted copy available for this user");
    }

    const encryptedCopy = copy as { epk: string; salt: string; iv: string; key: string };
    const ephPublicKey = await importRecipientPublicKey(encryptedCopy.epk);
    const privateKey = await importPrivateKeyFromPkcs8B64(privateKeyPkcs8B64);
    const sharedBits = await crypto.subtle.deriveBits(
      {
        name: "X25519",
        public: ephPublicKey,
      },
      privateKey,
      256
    );
    const wrappingKey = await deriveWrappingKey(sharedBits, b64UrlDecode(encryptedCopy.salt));
    const rawMessageKey = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(b64UrlDecode(encryptedCopy.iv)) },
        wrappingKey,
        new Uint8Array(b64UrlDecode(encryptedCopy.key))
      )
    );
    const messageKey = await crypto.subtle.importKey(
      "raw",
      rawMessageKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["decrypt"]
    );
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(b64UrlDecode(ivB64)) },
        messageKey,
        new Uint8Array(b64UrlDecode(ciphertextB64))
      )
    );

    return bytesToUtf8(plaintext);
  }

  const ephPublicKey = await importRecipientPublicKey(parsed.epk);
  const privateKey = await importPrivateKeyFromPkcs8B64(privateKeyPkcs8B64);

  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: ephPublicKey,
    },
    privateKey,
    256
  );

  const aesKey = await deriveAesKey(sharedBits, b64UrlDecode(parsed.salt));

  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64UrlDecode(ivB64)) },
      aesKey,
      new Uint8Array(b64UrlDecode(ciphertextB64))
    )
  );

  return bytesToUtf8(plaintext);
}
