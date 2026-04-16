// Frontend security updates by Rodrigo P Gomes and Negin Karimi.
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8080";
const TOKEN_STORAGE_KEY = "token";

export function getToken(): string | null {
  const sessionToken = sessionStorage.getItem(TOKEN_STORAGE_KEY);
  if (sessionToken) {
    return sessionToken;
  }

  // Migrate legacy tokens out of persistent storage to reduce exposure.
  const legacyToken = localStorage.getItem(TOKEN_STORAGE_KEY);
  if (legacyToken) {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, legacyToken);
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    return legacyToken;
  }

  return null;
}

export function setToken(token: string) {
  sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export async function apiRequest(
  method: string,
  path: string,
  body?: Record<string, unknown>
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
    }
    const text = await res.text();
    throw new Error(text || "Request failed");
  }

  return res.json();
}
