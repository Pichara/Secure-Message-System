import { create } from "zustand";

interface ChatStore {
  currentWith: string | null;
  setCurrentWith: (value: string | null) => void;
}

export const useChatStore = create<ChatStore>((set: (partial: Partial<ChatStore>) => void) => ({
  currentWith: null,
  setCurrentWith: (value: string | null) => set({ currentWith: value }),
}));