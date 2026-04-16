import { useState } from "react";
import { register } from "../api/auth";
import { useNavigate, Link } from "react-router-dom";
import { decryptPrivateKey, encryptPrivateKey, generateKeypair } from "../crypto/keys";
import { saveEncryptedPrivateKey, savePublicKey, saveUnlockedPrivateKeyRawB64 } from "../crypto/storage";

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  .reg-root {
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #F5F2ED;
    font-family: 'DM Sans', sans-serif;
  }

  .reg-card {
    width: 380px;
    background: #FEFCF9;
    border: 1px solid #E8E2D9;
    border-radius: 16px;
    padding: 40px 36px;
    box-shadow: 0 2px 24px rgba(60,50,30,0.07);
  }

  .reg-logo {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 32px;
  }

  .reg-logo-mark {
    width: 32px;
    height: 32px;
    background: #2C2925;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .reg-logo-mark svg {
    width: 16px;
    height: 16px;
    color: #F5F2ED;
  }

  .reg-logo-text {
    font-size: 15px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.3px;
  }

  .reg-title {
    font-size: 22px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.5px;
    margin-bottom: 6px;
  }

  .reg-subtitle {
    font-size: 14px;
    color: #8A8078;
    margin-bottom: 28px;
  }

  .reg-field {
    margin-bottom: 14px;
  }

  .reg-label {
    display: block;
    font-size: 12px;
    font-weight: 500;
    color: #6B6560;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 6px;
  }

  .reg-input {
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

  .reg-input::placeholder { color: #B8B0A6; }
  .reg-input:focus { border-color: #2C2925; }

  .reg-notice {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    background: #F0EDE7;
    border: 1px solid #E0DAD0;
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 16px;
    font-size: 12.5px;
    color: #6B6560;
    line-height: 1.5;
  }

  .reg-notice svg {
    flex-shrink: 0;
    margin-top: 1px;
    width: 14px;
    height: 14px;
    color: #8A8078;
  }

  .reg-btn {
    width: 100%;
    padding: 12px;
    margin-top: 4px;
    background: #2C2925;
    color: #F5F2ED;
    border: none;
    border-radius: 8px;
    font-family: 'DM Sans', sans-serif;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
  }

  .reg-btn:hover { background: #1A1714; }
  .reg-btn:active { transform: scale(0.99); }
  .reg-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .reg-footer {
    margin-top: 20px;
    text-align: center;
    font-size: 13px;
    color: #8A8078;
  }

  .reg-footer a {
    color: #2C2925;
    font-weight: 500;
    text-decoration: none;
  }

  .reg-footer a:hover { text-decoration: underline; }
`;

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async () => {
    if (!username || !password) return;
    setLoading(true);
    try {
      const kp = await generateKeypair();
      const encryptedPrivateKey = await encryptPrivateKey(kp.privateKeyPkcs8B64, password);

      await register({
        username,
        password,
        public_key: kp.publicKeyB64,
        encrypted_private_key: encryptedPrivateKey,
      });

      savePublicKey(kp.publicKeyB64);
      saveEncryptedPrivateKey(encryptedPrivateKey);

      const unlocked = await decryptPrivateKey(encryptedPrivateKey, password);
      saveUnlockedPrivateKeyRawB64(unlocked);

      navigate("/login");
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleRegister();
  };

  return (
    <>
      <style>{styles}</style>
      <div className="reg-root">
        <div className="reg-card">
          <div className="reg-logo">
            <div className="reg-logo-mark">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M2 4a2 2 0 012-2h8a2 2 0 012 2v6a2 2 0 01-2 2H6l-4 2V4z"/>
              </svg>
            </div>
            <span className="reg-logo-text">Cipher</span>
          </div>

          <h1 className="reg-title">Create an account</h1>
          <p className="reg-subtitle">Your keys are generated locally</p>

          <div className="reg-field">
            <label className="reg-label">Username</label>
            <input
              className="reg-input"
              placeholder="choose a username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={handleKeyDown}
              autoFocus
            />
          </div>

          <div className="reg-field">
            <label className="reg-label">Password</label>
            <input
              className="reg-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>

          <div className="reg-notice">
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <circle cx="8" cy="8" r="6"/>
              <path d="M8 7v4M8 5.5v.5"/>
            </svg>
            Your password encrypts your private key. It cannot be recovered if lost.
          </div>

          <button className="reg-btn" onClick={handleRegister} disabled={loading || !username || !password}>
            {loading ? "Generating keys…" : "Create account"}
          </button>

          <div className="reg-footer">
            Already have an account?{" "}
            <Link to="/login">Sign in</Link>
          </div>
        </div>
      </div>
    </>
  );
}