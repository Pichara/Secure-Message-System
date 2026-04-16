export interface AuthState {
  username: string;
  token: string;
  role: "user" | "admin";
}