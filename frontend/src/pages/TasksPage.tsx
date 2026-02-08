import { useEffect, useState } from 'react';
import { api, type TaskData } from '../lib/api';

export function TasksPage() {
  const [tasks, setTasks] = useState<TaskData[]>([]);
  const [error, setError] = useState('');

  const load = () => api.getTasks().then((d) => setTasks(d.tasks)).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const statusColor = (s: string) => {
    if (s === 'succeeded') return 'var(--green)';
    if (s === 'failed' || s === 'cancelled') return 'var(--red)';
    if (s === 'running') return 'var(--accent)';
    if (s === 'queued') return 'var(--yellow)';
    return 'var(--yellow)';
  };

  return (
    <>
      <h2>Queue</h2>
      <p className="section-desc">Task queue showing pending, running, and completed tasks.</p>

      {error && <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>}

      <table>
        <thead>
          <tr>
            <th>ID</th><th>Status</th><th>Provider</th><th>Prompt</th><th>Result</th><th>Created</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {tasks.map((t) => (
            <tr key={t.id}>
              <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{t.id}</td>
              <td>
                <span className="pill" style={{ color: statusColor(t.status) }}>
                  <span className="pill-dot" />{t.status}
                </span>
              </td>
              <td>{t.provider}</td>
              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.prompt_text}</td>
              <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12, color: t.error_text ? 'var(--red)' : undefined }}>
                {t.error_text || t.result_text || '—'}
              </td>
              <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{t.created_at}</td>
              <td>
                <div style={{ display: 'flex', gap: 4 }}>
                  {t.status === 'queued' && (
                    <button className="btn btn-sm btn-danger" onClick={() => { api.cancelTask(t.id).then(load); }}>Cancel</button>
                  )}
                  {(t.status === 'failed' || t.status === 'cancelled') && (
                    <button className="btn btn-sm" onClick={() => { api.retryTask(t.id).then(load); }}>Retry</button>
                  )}
                </div>
              </td>
            </tr>
          ))}
          {tasks.length === 0 && (
            <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: 32 }}>No tasks</td></tr>
          )}
        </tbody>
      </table>
    </>
  );
}
