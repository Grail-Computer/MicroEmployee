import { useEffect, useState } from 'react';
import { api, type SettingsData } from '../lib/api';

export function SettingsPage() {
  const [data, setData] = useState<SettingsData | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [secretBusy, setSecretBusy] = useState('');
  const [secrets, setSecrets] = useState({
    openai: '',
    slack_signing: '',
    slack_bot: '',
    telegram_bot: '',
    telegram_webhook: '',
    brave: '',
  });

  const load = () =>
    api
      .getSettings()
      .then((d) => {
        setData(d);
        setError('');
      })
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  if (!data) {
    if (error) return <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>;
    return <div className="loading">Loading…</div>;
  }

  const update = (key: keyof SettingsData, value: string | number | boolean) => {
    setData((prev) => prev ? { ...prev, [key]: value } : prev);
    setSaved(false);
  };

  const save = async () => {
    if (!data) return;
    setSaving(true);
    try {
      await api.saveSettings(data);
      setError('');
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed');
    }
    setSaving(false);
  };

  const saveSecret = async (key: keyof typeof secrets) => {
    const value = secrets[key].trim();
    if (!value) {
      setError('Secret value is empty');
      return;
    }
    setSecretBusy(key);
    try {
      await api.setSecret(key, value);
      setSecrets((prev) => ({ ...prev, [key]: '' }));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Secret save failed');
    }
    setSecretBusy('');
  };

  const clearSecret = async (key: keyof typeof secrets) => {
    setSecretBusy(key);
    try {
      await api.deleteSecret(key);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Secret clear failed');
    }
    setSecretBusy('');
  };

  const secretRow = (label: string, key: string, isSet: boolean) => (
    <div className="kv-item" key={key}>
      <div className="kv-label">{label}</div>
      <div className="kv-value" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className={`pill ${isSet ? 'pill-ok' : 'pill-bad'}`}>
          <span className="pill-dot" />{isSet ? 'Set' : 'Not set'}
        </span>
      </div>
    </div>
  );

  const secretManagerRow = (
    label: string,
    key: keyof typeof secrets,
    placeholder?: string,
  ) => (
    <div className="form-group" key={key}>
      <label className="form-label">{label}</label>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <input
          className="form-input"
          type="password"
          value={secrets[key]}
          onChange={(e) => setSecrets((prev) => ({ ...prev, [key]: e.target.value }))}
          placeholder={placeholder}
          style={{ flex: 1 }}
        />
        <button className="btn btn-sm" onClick={() => saveSecret(key)} disabled={secretBusy === key}>
          {secretBusy === key ? 'Saving…' : 'Save'}
        </button>
        <button className="btn btn-sm btn-danger" onClick={() => clearSecret(key)} disabled={secretBusy === key}>
          Clear
        </button>
      </div>
    </div>
  );

  return (
    <>
      <h2>Settings</h2>
      <p className="section-desc">Configure your agent's behavior, integrations, and permissions.</p>
      {error && <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>}

      <div className="card">
        <div className="card-title">Agent Identity</div>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={data.agent_name} onChange={(e) => update('agent_name', e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label">Role Description</label>
          <textarea className="form-textarea" rows={3} value={data.role_description} onChange={(e) => update('role_description', e.target.value)} />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Model</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <div className="form-group">
            <label className="form-label">Model</label>
            <input className="form-input" value={data.model} onChange={(e) => update('model', e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Reasoning Effort</label>
            <select className="form-select" value={data.reasoning_effort} onChange={(e) => update('reasoning_effort', e.target.value)}>
              <option value="">Default</option>
              <option value="none">none</option>
              <option value="minimal">minimal</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="xhigh">xhigh</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Reasoning Summary</label>
            <select className="form-select" value={data.reasoning_summary} onChange={(e) => update('reasoning_summary', e.target.value)}>
              <option value="">Default</option>
              <option value="auto">auto</option>
              <option value="concise">concise</option>
              <option value="detailed">detailed</option>
              <option value="none">none</option>
            </select>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Context Last N Messages</label>
          <input className="form-input" type="number" value={data.context_last_n} onChange={(e) => update('context_last_n', parseInt(e.target.value) || 0)} style={{ width: 120 }} />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Permissions</div>
        <div className="form-group">
          <label className="form-label">Permissions Mode</label>
          <select className="form-select" value={data.permissions_mode} onChange={(e) => update('permissions_mode', e.target.value)} style={{ width: 200 }}>
            <option value="read">Read-only</option>
            <option value="full">Full</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Command Approval Mode</label>
          <select className="form-select" value={data.command_approval_mode} onChange={(e) => update('command_approval_mode', e.target.value)} style={{ width: 200 }}>
            <option value="guardrails">Guardrails</option>
            <option value="always_ask">Always ask</option>
            <option value="auto">Auto-approve (not recommended)</option>
          </select>
        </div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.shell_network_access} onChange={(e) => update('shell_network_access', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Shell Network Access</label>
        </div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.allow_context_writes} onChange={(e) => update('allow_context_writes', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Allow Context Writes</label>
        </div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.auto_apply_guardrail_tighten} onChange={(e) => update('auto_apply_guardrail_tighten', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Auto-apply Guardrail Tighten</label>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Slack</div>
        <div className="form-group">
          <label className="form-label">Allow From (comma-separated user IDs)</label>
          <input className="form-input" value={data.slack_allow_from} onChange={(e) => update('slack_allow_from', e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label">Allow Channels (comma-separated)</label>
          <input className="form-input" value={data.slack_allow_channels} onChange={(e) => update('slack_allow_channels', e.target.value)} />
        </div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.allow_slack_mcp} onChange={(e) => update('allow_slack_mcp', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Enable Slack MCP Tools</label>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Telegram</div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.allow_telegram} onChange={(e) => update('allow_telegram', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Enable Telegram</label>
        </div>
        <div className="form-group">
          <label className="form-label">Allow From (comma-separated user IDs)</label>
          <input className="form-input" value={data.telegram_allow_from} onChange={(e) => update('telegram_allow_from', e.target.value)} />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Web Tools</div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.allow_web_mcp} onChange={(e) => update('allow_web_mcp', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Enable Web MCP Tools</label>
        </div>
        <div className="form-group">
          <label className="form-label">Allow Domains</label>
          <input className="form-input" value={data.web_allow_domains} onChange={(e) => update('web_allow_domains', e.target.value)} />
        </div>
        <div className="form-group">
          <label className="form-label">Deny Domains</label>
          <input className="form-input" value={data.web_deny_domains} onChange={(e) => update('web_deny_domains', e.target.value)} />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Cron</div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.allow_cron} onChange={(e) => update('allow_cron', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Enable Cron Jobs</label>
        </div>
        <div className="form-checkbox-row">
          <input type="checkbox" checked={data.auto_apply_cron_jobs} onChange={(e) => update('auto_apply_cron_jobs', e.target.checked)} />
          <label className="form-label" style={{ margin: 0 }}>Auto-apply Cron Jobs</label>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Extra MCP Config</div>
        <div className="form-group">
          <textarea className="form-textarea" rows={5} value={data.extra_mcp_config} onChange={(e) => update('extra_mcp_config', e.target.value)} placeholder="JSON or TOML config for extra MCP servers…" />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Credentials</div>
        <div className="kv-grid">
          {secretRow('Master Key', 'master_key', data.master_key_set)}
          {secretRow('OpenAI API Key', 'openai', data.openai_api_key_set)}
          {secretRow('Slack Signing Secret', 'slack_signing', data.slack_signing_secret_set)}
          {secretRow('Slack Bot Token', 'slack_bot', data.slack_bot_token_set)}
          {secretRow('Telegram Bot Token', 'telegram_bot', data.telegram_bot_token_set)}
          {secretRow('Telegram Webhook Secret', 'telegram_webhook', data.telegram_webhook_secret_set)}
          {secretRow('Brave Search API Key', 'brave', data.brave_search_api_key_set)}
        </div>
      </div>

      <div className="card">
        <div className="card-title">Manage Secrets</div>
        {data.master_key_set ? (
          <>
            <p className="section-desc" style={{ marginTop: 0 }}>
              Environment variables take precedence over stored secrets.
            </p>
            {secretManagerRow('OpenAI API Key', 'openai', 'sk-…')}
            {secretManagerRow('Slack Signing Secret', 'slack_signing')}
            {secretManagerRow('Slack Bot Token', 'slack_bot', 'xoxb-…')}
            {secretManagerRow('Telegram Bot Token', 'telegram_bot', '123456:ABC…')}
            {secretManagerRow('Telegram Webhook Secret', 'telegram_webhook')}
            {secretManagerRow('Brave Search API Key', 'brave', 'BSA-…')}
          </>
        ) : (
          <p className="section-desc" style={{ marginTop: 0 }}>
            Set <span className="pill">GRAIL_MASTER_KEY</span> to enable storing secrets in SQLite.
            Otherwise, set these as environment variables.
          </p>
        )}
      </div>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <button className="btn btn-primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save Settings'}
        </button>
        {saved && <span style={{ color: 'var(--green)', fontSize: 13 }}>✓ Saved</span>}
      </div>
    </>
  );
}
