import { apiRequest } from "./client";

export async function getAdminUsers() {
  return apiRequest("GET", "/api/admin/users");
}

export async function deleteAdminUser(username: string) {
  return apiRequest("DELETE", `/api/admin/users/${encodeURIComponent(username)}`);
}