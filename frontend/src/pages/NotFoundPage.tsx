import { Link } from "react-router-dom";

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }

  .notfound-root {
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: #F5F2ED;
    font-family: 'DM Sans', sans-serif;
    text-align: center;
  }

  .notfound-code {
    font-family: 'DM Mono', monospace;
    font-size: 72px;
    font-weight: 500;
    color: #E0DAD0;
    letter-spacing: -3px;
    line-height: 1;
    margin-bottom: 16px;
  }

  .notfound-title {
    font-size: 20px;
    font-weight: 600;
    color: #2C2925;
    letter-spacing: -0.4px;
    margin-bottom: 8px;
  }

  .notfound-sub {
    font-size: 14px;
    color: #8A8078;
    margin-bottom: 28px;
  }

  .notfound-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 10px 20px;
    background: #2C2925;
    color: #F5F2ED;
    border-radius: 8px;
    font-size: 13.5px;
    font-weight: 500;
    text-decoration: none;
    transition: background 0.15s;
  }

  .notfound-link:hover { background: #1A1714; }
`;

export default function NotFoundPage() {
  return (
    <>
      <style>{styles}</style>
      <div className="notfound-root">
        <div>
          <div className="notfound-code">404</div>
          <h1 className="notfound-title">Page not found</h1>
          <p className="notfound-sub">The page you're looking for doesn't exist.</p>
          <Link to="/" className="notfound-link">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M10 3L5 8l5 5"/>
            </svg>
            Back to home
          </Link>
        </div>
      </div>
    </>
  );
}