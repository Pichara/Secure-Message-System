export function saveEncryptedPrivateKey(value: string) {
  localStorage.setItem("encrypted_private_key", value);
}

export function getEncryptedPrivateKey(): string | null {
  return localStorage.getItem("encrypted_private_key");
}

export function savePublicKey(value: string) {
  localStorage.setItem("public_key", value);
}

export function getPublicKeyLocal(): string | null {
  return localStorage.getItem("public_key");
}

export function clearCryptoStorage() {
  localStorage.removeItem("encrypted_private_key");
  localStorage.removeItem("public_key");
  sessionStorage.removeItem("private_key_raw_b64");
}

export function saveUnlockedPrivateKeyRawB64(value: string) {
  sessionStorage.setItem("private_key_raw_b64", value);
}

export function getUnlockedPrivateKeyRawB64(): string | null {
  return sessionStorage.getItem("private_key_raw_b64");
}