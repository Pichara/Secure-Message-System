import { create } from "zustand";
import type { AuthState } from "../types/auth";

interface AuthStore {
  auth: AuthState | null;
  setAuth: (auth: AuthState) => void;
  clearAuth: () => void;
}

export const useAuthStore = create<AuthStore>((set: (state: Partial<AuthStore>) => void) => ({
  auth: null,
  setAuth: (auth: AuthState) => set({ auth }),
  clearAuth: () => set({ auth: null }),
}));