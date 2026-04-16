import { apiRequest, setToken, clearToken } from "./client";

interface RegisterPayload extends Record<string, unknown> {
  username: string;
  password: string;
  email?: string;
}

export async function login(username: string, password: string) {
  const res = await apiRequest("POST", "/api/login", {
    username,
    password,
  });

  setToken(res.token);
  return res;
}

export async function register(payload: RegisterPayload) {
  return apiRequest("POST", "/api/register", payload);
}

export async function logout() {
  try {
    await apiRequest("POST", "/api/logout");
  } catch (e) {
    // Ignore logout errors
  }
  clearToken();
}

export async function me() {
  return apiRequest("GET", "/api/me");
}