import { useEffect, useState } from 'react';
import { api, type GuardrailData } from '../lib/api';

export function GuardrailsPage() {
  const [rules, setRules] = useState<GuardrailData[]>([]);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [kind, setKind] = useState('command');
  const [action, setAction] = useState('require_approval');
  const [priority, setPriority] = useState('100');
  const [patternKind, setPatternKind] = useState('regex');
  const [pattern, setPattern] = useState('');

  const load = () => api.getGuardrails().then((d) => setRules(d.rules)).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const addRule = async () => {
    try {
      await api.addGuardrail({ kind, action, priority: parseInt(priority), name, pattern_kind: patternKind, pattern });
      setName(''); setPattern('');
      load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
  };

  return (
    <>
      <h2>Guardrails</h2>
      <p className="section-desc">Command execution guardrails.</p>

      {error && <div className="card" style={{ color: 'var(--red)' }}>Error: {error}</div>}

      <div className="card">
        <div className="card-title">Add Rule</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Kind</label>
            <select className="form-select" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="command">command</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Action</label>
            <select className="form-select" value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="require_approval">require_approval</option>
              <option value="deny">deny</option>
              <option value="allow">allow</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Pattern Kind</label>
            <select className="form-select" value={patternKind} onChange={(e) => setPatternKind(e.target.value)}>
              <option value="regex">regex</option>
              <option value="exact">exact</option>
              <option value="substring">substring</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Pattern</label>
            <input className="form-input" value={pattern} onChange={(e) => setPattern(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Priority</label>
            <input className="form-input" type="number" value={priority} onChange={(e) => setPriority(e.target.value)} />
          </div>
        </div>
        <button className="btn btn-primary" onClick={addRule}>Add Rule</button>
      </div>

      <table>
        <thead>
          <tr><th>Name</th><th>Kind</th><th>Action</th><th>Pattern</th><th>Priority</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td>
              <td>{r.kind}</td>
              <td>{r.action}</td>
              <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{r.pattern}</td>
              <td>{r.priority}</td>
              <td>
                <span className={`pill ${r.enabled ? 'pill-ok' : 'pill-bad'}`}>
                  <span className="pill-dot" />{r.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </td>
              <td>
                <div style={{ display: 'flex', gap: 4 }}>
                  {r.enabled ? (
                    <button className="btn btn-sm" onClick={() => { api.disableGuardrail(r.id).then(load); }}>Disable</button>
                  ) : (
                    <button className="btn btn-sm" onClick={() => { api.enableGuardrail(r.id).then(load); }}>Enable</button>
                  )}
                  <button className="btn btn-sm btn-danger" onClick={() => { api.deleteGuardrail(r.id).then(load); }}>Delete</button>
                </div>
              </td>
            </tr>
          ))}
          {rules.length === 0 && (
            <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: 32 }}>No guardrail rules</td></tr>
          )}
        </tbody>
      </table>
    </>
  );
}
