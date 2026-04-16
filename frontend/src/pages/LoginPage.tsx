import { useEffect, useState } from "react";
import { login, me } from "../api/auth";
import { useNavigate, Link } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { saveEncryptedPrivateKey, savePublicKey, saveUnlockedPrivateKeyRawB64 } from "../crypto/storage";
import { decryptPrivateKey } from "../crypto/keys";

interface AuthState {
  auth: { username: string; token: string; role: "user" | "admin" } | null;
  setAuth: (auth: { username: string; token: string; role: "user" | "admin" }) => void;
  clearAuth: () => void;
}

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  .login-root {
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #F5F2ED;
    font-family: 'DM Sans', sans-serif;
  }

  .login-card {
    width: 380px;
    background: #FEFCF9;
    border: 1px solid #E8E2D9;
    border-radius: 16px;
    padding: 40px 36px;
    box-shadow: 0 2px 24px rgba(60,50,30,0.07);
  }

  .login-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
  }

  .login-logo-mark {
    width: 32px;
    height: 32px;
    background: #2C2925;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .login-logo-mark svg {
    width: 16px;
    height: 16px;
    color: #F5F2ED;
  }

  .login-logo-text {
    font-size: 15px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.3px;
  }

  .login-title {
    font-size: 22px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.5px;
    margin-bottom: 6px;
  }

  .login-subtitle {
    font-size: 14px;
    color: #8A8078;
    margin-bottom: 28px;
  }

  .login-field {
    margin-bottom: 14px;
  }

  .login-label {
    display: block;
    font-size: 12px;
    font-weight: 500;
    color: #6B6560;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 6px;
  }

  .login-input {
    width: 100%;
    padding: 11px 14px;
    border: 1.5px solid #E0DAD0;
    border-radius: 8px;
    background: #FEFCF9;
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    color: #2C2925;
    outline: none;
    transition: border-color 0.15s;
  }

  .login-input::placeholder { color: #B8B0A6; }

  .login-input:focus {
    border-color: #2C2925;
  }

  .login-btn {
    width: 100%;
    padding: 12px;
    margin-top: 8px;
    background: #2C2925;
    color: #F5F2ED;
    border: none;
    border-radius: 8px;
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
    letter-spacing: 0.1px;
  }

  .login-btn:hover { background: #1A1714; }
  .login-btn:active { transform: scale(0.99); }

  .login-footer {
    margin-top: 20px;
    text-align: center;
    font-size: 13px;
    color: #8A8078;
  }

  .login-footer a {
    color: #2C2925;
    font-weight: 500;
    text-decoration: none;
  }

  .login-footer a:hover { text-decoration: underline; }
`;

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const auth = useAuthStore((s: AuthState) => s.auth);
  const setAuth = useAuthStore((s: AuthState) => s.setAuth);

  useEffect(() => {
    if (auth) navigate(auth.role === "admin" ? "/admin" : "/");
  }, [auth, navigate]);

  const handleLogin = async () => {
    setLoading(true);
    try {
      await login(username, password);
      const user = await me();

      if (user.public_key) savePublicKey(user.public_key);
      if (user.encrypted_private_key) {
        saveEncryptedPrivateKey(user.encrypted_private_key);
        try {
          const unlocked = await decryptPrivateKey(user.encrypted_private_key, password);
          saveUnlockedPrivateKeyRawB64(unlocked);
        } catch {
          console.warn("Could not unlock private key after login");
        }
      }

      setAuth({ username: user.username, token: localStorage.getItem("token")!, role: user.role });
      navigate(user.role === "admin" ? "/admin" : "/");
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleLogin();
  };

  return (
    <>
      <style>{styles}</style>
      <div className="login-root">
        <div className="login-card">
          <div className="login-logo">
            <div className="login-logo-mark">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M2 4a2 2 0 012-2h8a2 2 0 012 2v6a2 2 0 01-2 2H6l-4 2V4z"/>
              </svg>
            </div>
            <span className="login-logo-text">Cipher</span>
          </div>

          <h1 className="login-title">Welcome back</h1>
          <p className="login-subtitle">Sign in to your encrypted messenger</p>

          <div className="login-field">
            <label className="login-label">Username</label>
            <input
              className="login-input"
              placeholder="your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={handleKeyDown}
              autoFocus
            />
          </div>

          <div className="login-field">
            <label className="login-label">Password</label>
            <input
              className="login-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>

          <button className="login-btn" onClick={handleLogin} disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </button>

          <div className="login-footer">
            No account?{" "}
            <Link to="/register">Create one</Link>
          </div>
        </div>
      </div>
    </>
  );
}