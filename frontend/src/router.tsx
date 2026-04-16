// Frontend security updates by Rodrigo P Gomes and Negin Karimi.
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState, type ReactNode } from "react";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import ChatPage from "./pages/ChatPage";
import AdminPage from "./pages/AdminPage";
import { useAuthStore } from "./store/authStore";
import type { AuthState } from "./types/auth";
import { me } from "./api/auth";
import { clearToken, getToken } from "./api/client";

function PrivateRoute({ children, restoring }: { children: ReactNode; restoring: boolean }) {
  const auth = useAuthStore((s: { auth: AuthState | null }) => s.auth);
  if (restoring) {
    return null;
  }
  return auth ? children : <Navigate to="/login" replace />;
}

function AdminRoute({ children, restoring }: { children: ReactNode; restoring: boolean }) {
  const auth = useAuthStore((s: { auth: AuthState | null }) => s.auth);
  if (restoring) {
    return null;
  }
  if (!auth) {
    return <Navigate to="/login" replace />;
  }
  return auth.role === "admin" ? children : <Navigate to="/" replace />;
}

export default function Router() {
  const auth = useAuthStore((s: { auth: AuthState | null }) => s.auth);
  const setAuth = useAuthStore((s: { setAuth: (auth: AuthState) => void }) => s.setAuth);
  const clearAuth = useAuthStore((s: { clearAuth: () => void }) => s.clearAuth);
  const [restoring, setRestoring] = useState(true);

  useEffect(() => {
    let active = true;

    async function restoreSession() {
      const token = getToken();
      if (!token) {
        if (active) {
          clearAuth();
          setRestoring(false);
        }
        return;
      }

      if (auth) {
        if (active) {
          setRestoring(false);
        }
        return;
      }

      try {
        const user = await me();
        if (!active) {
          return;
        }
        setAuth({ username: user.username, token, role: user.role });
      } catch {
        clearToken();
        if (active) {
          clearAuth();
        }
      } finally {
        if (active) {
          setRestoring(false);
        }
      }
    }

    restoreSession();
    return () => {
      active = false;
    };
  }, [auth, clearAuth, setAuth]);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        <Route
          path="/"
          element={
            <PrivateRoute restoring={restoring}>
              <ChatPage />
            </PrivateRoute>
          }
        />

        <Route
          path="/admin"
          element={
            <AdminRoute restoring={restoring}>
              <AdminPage />
            </AdminRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
