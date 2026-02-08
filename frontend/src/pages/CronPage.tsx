import { useEffect, useState } from 'react';
import { api, type CronData, type CronJobData } from '../lib/api';

export function CronPage() {
  const [data, setData] = useState<CronData | null>(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [channelId, setChannelId] = useState('');
  const [threadTs, setThreadTs] = useState('');
  const [prompt, setPrompt] = useState('');
  const [schedKind, setSchedKind] = useState('every');
  const [everySeconds, setEverySeconds] = useState('3600');
  const [cronExpr, setCronExpr] = useState('');

  const load = () =>
    api
      .getCron()
      .then((d) => {
        setData(d);
        setError('');
      })
      .catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const addJob = async () => {
    try {
      await api.addCronJob({
        name, channel_id: channelId, thread_ts: threadTs, prompt_text: prompt,
        schedule_kind: schedKind,
        every_seconds: schedKind === 'every' ? parseInt(everySeconds) : undefined,
        cron_expr: schedKind === 'cron' ? cronExpr : undefined,
      });
      setName(''); setChannelId(''); setThreadTs(''); setPrompt('');
      load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
  };

  if (!data) {
    if (error) return <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>;
    return <div className="loading">Loading…</div>;
  }

  return (
    <>
      <h2>Cron Jobs</h2>
      <p className="section-desc">Scheduled tasks that run automatically on a timer.</p>

      {error && <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>}

      <div className="card">
        <div className="card-title">Add Job</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Schedule Type</label>
            <select className="form-select" value={schedKind} onChange={(e) => setSchedKind(e.target.value)}>
              <option value="every">Every N seconds</option>
              <option value="cron">Cron expression</option>
            </select>
          </div>
          {schedKind === 'every' && (
            <div className="form-group">
              <label className="form-label">Every (seconds)</label>
              <input className="form-input" type="number" value={everySeconds} onChange={(e) => setEverySeconds(e.target.value)} />
            </div>
          )}
          {schedKind === 'cron' && (
            <div className="form-group">
              <label className="form-label">Cron Expression</label>
              <input className="form-input" value={cronExpr} onChange={(e) => setCronExpr(e.target.value)} placeholder="0 0 * * *" />
            </div>
          )}
          <div className="form-group">
            <label className="form-label">Channel ID</label>
            <input className="form-input" value={channelId} onChange={(e) => setChannelId(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Thread TS (optional)</label>
            <input className="form-input" value={threadTs} onChange={(e) => setThreadTs(e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Prompt</label>
          <textarea className="form-textarea" rows={3} value={prompt} onChange={(e) => setPrompt(e.target.value)} />
        </div>
        <button className="btn btn-primary" onClick={addJob}>Add Job</button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Name</th><th>Schedule</th><th>Status</th><th>Next Run</th><th>Last Run</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {data.jobs.map((j: CronJobData) => (
            <tr key={j.id}>
              <td>{j.name}</td>
              <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{j.schedule}</td>
              <td>
                <span className={`pill ${j.enabled ? 'pill-ok' : 'pill-bad'}`}>
                  <span className="pill-dot" />{j.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </td>
              <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{j.next_run_at || '—'}</td>
              <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{j.last_run_at || '—'}</td>
              <td>
                <div style={{ display: 'flex', gap: 4 }}>
                  {j.enabled ? (
                    <button className="btn btn-sm" onClick={() => { api.disableCronJob(j.id).then(load); }}>Disable</button>
                  ) : (
                    <button className="btn btn-sm" onClick={() => { api.enableCronJob(j.id).then(load); }}>Enable</button>
                  )}
                  <button className="btn btn-sm btn-danger" onClick={() => { api.deleteCronJob(j.id).then(load); }}>Delete</button>
                </div>
              </td>
            </tr>
          ))}
          {data.jobs.length === 0 && (
            <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: 32 }}>No cron jobs</td></tr>
          )}
        </tbody>
      </table>
    </>
  );
}
