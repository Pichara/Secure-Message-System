import { apiRequest } from "./client";

export async function getMessages(withUser?: string) {
  const suffix = withUser ? `?with=${encodeURIComponent(withUser)}` : "";
  return apiRequest("GET", `/api/messages${suffix}`);
}

export async function sendMessage(payload: {
  recipient: string;
  encrypted_key: string;
  ciphertext: string;
  iv: string;
}) {
  return apiRequest("POST", "/api/messages", payload);
}

export async function getPublicKey(username: string) {
  return apiRequest("GET", `/api/users/${encodeURIComponent(username)}/public-key`);
}