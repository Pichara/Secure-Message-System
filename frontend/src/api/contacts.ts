import { apiRequest } from "./client";

export async function getContacts() {
  return apiRequest("GET", "/api/contacts");
}

export async function addContact(alias: string, username: string) {
  return apiRequest("POST", "/api/contacts", { alias, username });
}

export async function removeContact(alias: string) {
  return apiRequest("DELETE", `/api/contacts/${encodeURIComponent(alias)}`);
}