import { useEffect, useState } from 'react';
import { api, type AuthData } from '../lib/api';

export function AuthPage() {
  const [data, setData] = useState<AuthData | null>(null);
  const [error, setError] = useState('');
  const load = () =>
    api
      .getAuth()
      .then((d) => {
        setData(d);
        setError('');
      })
      .catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  if (!data) {
    if (error) return <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>;
    return <div className="loading">Loading…</div>;
  }

  const boolPill = (set: boolean) => (
    <span className={`pill ${set ? 'pill-ok' : 'pill-bad'}`}>
      <span className="pill-dot" />{set ? 'Set' : 'Not set'}
    </span>
  );

  return (
    <>
      <h2>Auth</h2>
      <p className="section-desc">API keys and Codex authentication.</p>
      {error && <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>}
      <div className="card">
        <div className="card-title">Credentials</div>
        <div className="kv-grid">
          <div className="kv-item"><div className="kv-label">OpenAI API Key</div><div className="kv-value">{boolPill(data.openai_api_key_set)}</div></div>
          <div className="kv-item"><div className="kv-label">Codex Auth File</div><div className="kv-value">{boolPill(data.codex_auth_file_set)}</div></div>
          <div className="kv-item"><div className="kv-label">Auth Mode</div><div className="kv-value">{data.codex_auth_mode}</div></div>
        </div>
      </div>
      <div className="card">
        <div className="card-title">Device Login</div>
        {data.device_login ? (
          <>
            <p style={{ fontSize: 13 }}>Status: <strong>{data.device_login.status}</strong> — Code: <code>{data.device_login.user_code}</code></p>
            {data.device_login.verification_url && <p><a href={data.device_login.verification_url} target="_blank" rel="noreferrer">Open verification URL</a></p>}
            <button className="btn btn-danger btn-sm" onClick={() => { api.cancelDeviceLogin().then(load); }}>Cancel</button>
          </>
        ) : (
          <button className="btn btn-primary" onClick={() => { api.startDeviceLogin().then(load); }}>Start Device Login</button>
        )}
      </div>
      <button className="btn btn-danger" style={{ marginTop: 16 }} onClick={() => { api.authLogout().then(load); }}>Logout</button>
    </>
  );
}
