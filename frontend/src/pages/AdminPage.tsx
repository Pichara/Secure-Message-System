import { useEffect, useState } from "react";
import { deleteAdminUser, getAdminUsers } from "../api/admin";
import { logout } from "../api/auth";
import { useAuthStore } from "../store/authStore";
import { useNavigate } from "react-router-dom";
import { clearCryptoStorage } from "../crypto/storage";

interface AuthUser { username: string; }
interface AuthState { auth: AuthUser | null; clearAuth: () => void; }

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }

  .admin-root {
    min-height: 100vh;
    background: #F5F2ED;
    font-family: 'DM Sans', sans-serif;
  }

  .admin-topbar {
    background: #FEFCF9;
    border-bottom: 1px solid #E8E2D9;
    padding: 0 32px;
    height: 58px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .admin-topbar-left {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .admin-logo-mark {
    width: 28px;
    height: 28px;
    background: #2C2925;
    border-radius: 7px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .admin-logo-mark svg {
    width: 14px;
    height: 14px;
    color: #F5F2ED;
  }

  .admin-logo-text {
    font-size: 14px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.3px;
  }

  .admin-divider {
    width: 1px;
    height: 18px;
    background: #E0DAD0;
    margin: 0 4px;
  }

  .admin-badge {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    color: #8A8078;
    background: #F0EDE7;
    border: 1px solid #E0DAD0;
    border-radius: 20px;
    padding: 2px 8px;
  }

  .admin-topbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .admin-signed-in {
    font-size: 12.5px;
    color: #8A8078;
  }

  .admin-btn {
    padding: 7px 14px;
    border: 1.5px solid #E0DAD0;
    border-radius: 8px;
    background: none;
    font-family: 'DM Sans', sans-serif;
    font-size: 13px;
    color: #6B6560;
    cursor: pointer;
    font-weight: 500;
    transition: border-color 0.15s, color 0.15s;
  }
  .admin-btn:hover { border-color: #2C2925; color: #2C2925; }

  .admin-btn-primary {
    padding: 7px 14px;
    border: none;
    border-radius: 8px;
    background: #2C2925;
    font-family: 'DM Sans', sans-serif;
    font-size: 13px;
    color: #F5F2ED;
    cursor: pointer;
    font-weight: 500;
    transition: background 0.15s;
  }
  .admin-btn-primary:hover { background: #1A1714; }

  .admin-content {
    max-width: 720px;
    margin: 40px auto;
    padding: 0 24px;
  }

  .admin-section-title {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.7px;
    text-transform: uppercase;
    color: #8A8078;
    margin-bottom: 12px;
  }

  .admin-card {
    background: #FEFCF9;
    border: 1px solid #E8E2D9;
    border-radius: 12px;
    overflow: hidden;
  }

  .admin-user-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid #F0EDE7;
    transition: background 0.1s;
  }

  .admin-user-row:last-child { border-bottom: none; }
  .admin-user-row:hover { background: #F7F4F0; }

  .admin-user-info {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .admin-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: #E8E2D9;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 600;
    color: #6B6560;
  }

  .admin-username {
    font-size: 13.5px;
    font-weight: 500;
    color: #2C2925;
    font-family: 'DM Mono', monospace;
  }

  .admin-delete-btn {
    padding: 5px 12px;
    border: 1.5px solid #E0DAD0;
    border-radius: 6px;
    background: none;
    font-family: 'DM Sans', sans-serif;
    font-size: 12px;
    color: #8A8078;
    cursor: pointer;
    font-weight: 500;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
  }
  .admin-delete-btn:hover {
    border-color: #C0392B;
    color: #C0392B;
    background: #FDF2F1;
  }

  .admin-empty {
    padding: 40px 20px;
    text-align: center;
    color: #B8B0A6;
    font-size: 13.5px;
  }

  .admin-stats {
    display: flex;
    gap: 12px;
    margin-bottom: 24px;
  }

  .admin-stat-card {
    flex: 1;
    background: #FEFCF9;
    border: 1px solid #E8E2D9;
    border-radius: 10px;
    padding: 16px 18px;
  }

  .admin-stat-label {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: #8A8078;
    margin-bottom: 6px;
  }

  .admin-stat-value {
    font-size: 26px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -1px;
    font-family: 'DM Mono', monospace;
  }
`;

export default function AdminPage() {
  const auth = useAuthStore((s: AuthState) => s.auth);
  const clearAuth = useAuthStore((s: AuthState) => s.clearAuth);
  const navigate = useNavigate();
  const [users, setUsers] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  const loadUsers = async () => {
    try {
      setLoading(true);
      const payload = await getAdminUsers();
      const rawUsers = Array.isArray(payload) ? payload : payload.users;

      const usernames: string[] = [];
      if (Array.isArray(rawUsers)) {
        for (const entry of rawUsers) {
          if (typeof entry === "string") usernames.push(entry);
          else if (entry && typeof entry === "object" && "username" in entry) {
            usernames.push(String((entry as Record<string, unknown>).username));
          }
        }
      }

      usernames.sort((a, b) => a.localeCompare(b));
      setUsers(usernames);
    } catch (e: unknown) {
      alert((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadUsers(); }, []);

  const handleDelete = async (username: string) => {
    if (!confirm(`Delete "${username}"? This cannot be undone.`)) return;
    try {
      await deleteAdminUser(username);
      await loadUsers();
    } catch (e: unknown) {
      alert((e as Error).message);
    }
  };

  const handleLogout = async () => {
    await logout();
    clearCryptoStorage();
    clearAuth();
    navigate("/login");
  };

  return (
    <>
      <style>{styles}</style>
      <div className="admin-root">
        <div className="admin-topbar">
          <div className="admin-topbar-left">
            <div className="admin-logo-mark">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M2 4a2 2 0 012-2h8a2 2 0 012 2v6a2 2 0 01-2 2H6l-4 2V4z"/>
              </svg>
            </div>
            <span className="admin-logo-text">Cipher</span>
            <div className="admin-divider" />
            <span className="admin-badge">Admin</span>
          </div>

          <div className="admin-topbar-right">
            <span className="admin-signed-in">{auth?.username}</span>
            <button className="admin-btn" onClick={loadUsers} disabled={loading}>
              {loading ? "Loading…" : "Refresh"}
            </button>
            <button className="admin-btn-primary" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </div>

        <div className="admin-content">
          <div className="admin-stats">
            <div className="admin-stat-card">
              <div className="admin-stat-label">Total users</div>
              <div className="admin-stat-value">{loading ? "—" : users.length}</div>
            </div>
            <div className="admin-stat-card">
              <div className="admin-stat-label">Status</div>
              <div className="admin-stat-value" style={{ fontSize: 16, marginTop: 4, fontFamily: "'DM Sans', sans-serif", letterSpacing: 0 }}>
                {loading ? "Loading…" : "Operational"}
              </div>
            </div>
          </div>

          <div className="admin-section-title">Registered users</div>
          <div className="admin-card">
            {loading && (
              <div className="admin-empty">Loading users…</div>
            )}
            {!loading && users.length === 0 && (
              <div className="admin-empty">No users found.</div>
            )}
            {!loading && users.map((username) => (
              <div key={username} className="admin-user-row">
                <div className="admin-user-info">
                  <div className="admin-avatar">
                    {username.charAt(0).toUpperCase()}
                  </div>
                  <span className="admin-username">{username}</span>
                </div>
                <button
                  className="admin-delete-btn"
                  onClick={() => handleDelete(username)}
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}