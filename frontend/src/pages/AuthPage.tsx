import { useEffect, useState } from 'react';
import { api, type AuthData } from '../lib/api';

function actionErrorMessage(e: unknown): string {
  return e instanceof Error ? e.message : 'Request failed';
}

export function AuthPage() {
  const [data, setData] = useState<AuthData | null>(null);
  const [error, setError] = useState('');
  const [busyAction, setBusyAction] = useState('');
  const [githubClientIdInput, setGithubClientIdInput] = useState('');

  const load = () =>
    api
      .getAuth()
      .then((d) => {
        setData(d);
        setGithubClientIdInput(d.github_client_id_value ?? '');
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

  const runAction = async (actionKey: string, action: () => Promise<void>) => {
    setBusyAction(actionKey);
    try {
      await action();
      await load();
    } catch (e) {
      setError(actionErrorMessage(e));
    }
    setBusyAction('');
  };

  const startGithubDeviceLogin = async () => {
    if (!data.github_client_id_set) {
      return;
    }

    const popup = window.open('about:blank', '_blank');
    setBusyAction('github_start');
    try {
      const out = await api.startGithubDeviceLogin();
      await load();
      if (out.verification_url) {
        if (popup) {
          try {
            popup.opener = null;
          } catch {
            // no-op
          }
          popup.location.href = out.verification_url;
        } else {
          window.open(out.verification_url, '_blank', 'noopener,noreferrer');
        }
      } else if (popup) {
        popup.close();
      }
      setError('');
    } catch (e) {
      if (popup) {
        popup.close();
      }
      setError(actionErrorMessage(e));
    }
    setBusyAction('');
  };

  const codexPending = data.device_login?.status === 'pending';
  const githubPending = data.github_device_login?.status === 'pending';

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
          <div className="kv-item"><div className="kv-label">GitHub Client ID</div><div className="kv-value">{boolPill(data.github_client_id_set)}</div></div>
          <div className="kv-item"><div className="kv-label">GitHub Token</div><div className="kv-value">{boolPill(data.github_token_set)}</div></div>
        </div>
      </div>
      <div className="card">
        <div className="card-title">Device Login</div>
        {data.device_login && (
          <>
            <p className="auth-meta">
              Status: <strong>{data.device_login.status}</strong>
              {' '}— Code: <code>{data.device_login.user_code}</code>
            </p>
            {data.device_login.status === 'failed' && data.device_login.error_text && (
              <p className="auth-error-text">Error: {data.device_login.error_text}</p>
            )}
            {codexPending && data.device_login.verification_url && (
              <p><a href={data.device_login.verification_url} target="_blank" rel="noreferrer">Open verification URL</a></p>
            )}
            {codexPending && (
              <button
                className="btn btn-danger btn-sm"
                disabled={busyAction === 'codex_cancel'}
                onClick={() => runAction('codex_cancel', () => api.cancelDeviceLogin().then(() => undefined))}
              >
                {busyAction === 'codex_cancel' ? 'Cancelling…' : 'Cancel'}
              </button>
            )}
          </>
        )}
        {!codexPending && (
          <button
            className="btn btn-primary"
            disabled={busyAction === 'codex_start'}
            onClick={() => runAction('codex_start', () => api.startDeviceLogin().then(() => undefined))}
          >
            {busyAction === 'codex_start' ? 'Starting…' : 'Start Device Login'}
          </button>
        )}
      </div>
      <div className="card">
        <div className="card-title">GitHub Device Login</div>
        <p className="auth-inline-note">
          Configure a GitHub OAuth app client ID. Environment variable <code>GITHUB_CLIENT_ID</code> overrides saved value.
        </p>
        <div className="auth-client-id-row">
          <input
            className="form-input"
            value={githubClientIdInput}
            onChange={(e) => setGithubClientIdInput(e.target.value)}
            placeholder="Iv1.0123456789abcdef"
            spellCheck={false}
          />
          <button
            className="btn btn-sm"
            disabled={busyAction === 'github_client_id_save'}
            onClick={() => runAction('github_client_id_save', () => api.setGithubClientId(githubClientIdInput).then(() => undefined))}
          >
            {busyAction === 'github_client_id_save' ? 'Saving…' : 'Save Client ID'}
          </button>
          <button
            className="btn btn-sm btn-danger"
            disabled={busyAction === 'github_client_id_clear'}
            onClick={() => {
              setGithubClientIdInput('');
              runAction('github_client_id_clear', () => api.setGithubClientId('').then(() => undefined));
            }}
          >
            {busyAction === 'github_client_id_clear' ? 'Clearing…' : 'Clear'}
          </button>
        </div>
        {data.github_client_id_source === 'env' && (
          <p className="auth-subtle">Using client ID from environment.</p>
        )}
        {!data.github_client_id_set && (
          <p className="auth-inline-note">
            Set <code>GITHUB_CLIENT_ID</code> in environment or save one above to enable GitHub device login.
          </p>
        )}
        {data.github_device_login && (
          <>
            <p className="auth-meta">
              Status: <strong>{data.github_device_login.status}</strong>
              {' '}— Code: <code>{data.github_device_login.user_code}</code>
            </p>
            {data.github_device_login.status === 'failed' && data.github_device_login.error_text && (
              <p className="auth-error-text">Error: {data.github_device_login.error_text}</p>
            )}
            {githubPending && data.github_device_login.verification_url && (
              <p><a href={data.github_device_login.verification_url} target="_blank" rel="noreferrer">Open verification URL</a></p>
            )}
            {githubPending && (
              <button
                className="btn btn-danger btn-sm"
                disabled={busyAction === 'github_cancel'}
                onClick={() => runAction('github_cancel', () => api.cancelGithubDeviceLogin().then(() => undefined))}
              >
                {busyAction === 'github_cancel' ? 'Cancelling…' : 'Cancel'}
              </button>
            )}
          </>
        )}
        {!githubPending && (
          <button
            className="btn btn-primary"
            disabled={!data.github_client_id_set || busyAction === 'github_start'}
            onClick={startGithubDeviceLogin}
          >
            {busyAction === 'github_start' ? 'Starting…' : 'Start GitHub Device Login'}
          </button>
        )}
        <div className="auth-actions">
          <button
            className="btn btn-danger btn-sm"
            disabled={busyAction === 'github_logout'}
            onClick={() => runAction('github_logout', () => api.githubLogout().then(() => undefined))}
          >
            {busyAction === 'github_logout' ? 'Logging out…' : 'Logout (Delete token)'}
          </button>
        </div>
      </div>
      <button
        className="btn btn-danger"
        style={{ marginTop: 16 }}
        disabled={busyAction === 'codex_logout'}
        onClick={() => runAction('codex_logout', () => api.authLogout().then(() => undefined))}
      >
        {busyAction === 'codex_logout' ? 'Logging out…' : 'Logout (Delete Codex auth)'}
      </button>
    </>
  );
}
