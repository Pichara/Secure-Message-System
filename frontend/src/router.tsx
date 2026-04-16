import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import ChatPage from "./pages/ChatPage";
import AdminPage from "./pages/AdminPage";
import { useAuthStore } from "./store/authStore";
import type { AuthState } from "./types/auth";

function PrivateRoute({ children }: { children: ReactNode }) {
  const auth = useAuthStore((s: { auth: AuthState | null }) => s.auth);
  return auth ? children : <Navigate to="/login" />;
}

export default function Router() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        <Route
          path="/"
          element={
            <PrivateRoute>
              <ChatPage />
            </PrivateRoute>
          }
        />

        <Route
          path="/admin"
          element={
            <PrivateRoute>
              <AdminPage />
            </PrivateRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
