import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, type TaskData, type TaskListItemData, type TaskTraceData } from '../lib/api';

export function TasksPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const selectedTaskId = useMemo(() => {
    const parsed = Number(id);
    return Number.isFinite(parsed) && Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
  }, [id]);

  const [tasks, setTasks] = useState<TaskListItemData[]>([]);
  const [detailTask, setDetailTask] = useState<TaskData | null>(null);
  const [traces, setTraces] = useState<TaskTraceData[]>([]);
  const [listError, setListError] = useState('');
  const [detailError, setDetailError] = useState('');

  const statusColor = (s: string) => {
    if (s === 'succeeded') return 'var(--green)';
    if (s === 'failed' || s === 'cancelled') return 'var(--red)';
    if (s === 'running') return 'var(--accent)';
    if (s === 'queued') return 'var(--yellow)';
    return 'var(--yellow)';
  };

  const loadList = async () => {
    try {
      const response = await api.getTasks();
      setTasks(response.tasks);
      setListError('');

      if (selectedTaskId) {
        const exists = response.tasks.some((task) => task.id === selectedTaskId);
        if (!exists) {
          setDetailTask(null);
          setTraces([]);
          navigate('/tasks', { replace: true });
        }
      }
    } catch (err) {
      setListError(err instanceof Error ? err.message : 'Failed to load task list');
    }
  };

  const loadDetail = async (taskId: number) => {
    try {
      const response = await api.getTask(taskId);
      setDetailTask(response.task);
      setTraces(response.traces);
      setDetailError('');
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Failed to load task details');
    }
  };

  useEffect(() => {
    void loadList();
    const timer = setInterval(() => {
      void loadList();
    }, 2500);
    return () => clearInterval(timer);
  }, [selectedTaskId, navigate]);

  useEffect(() => {
    if (!selectedTaskId) {
      setDetailTask(null);
      setTraces([]);
      setDetailError('');
      return;
    }

    void loadDetail(selectedTaskId);
    const timer = setInterval(() => {
      void loadDetail(selectedTaskId);
    }, 2500);
    return () => clearInterval(timer);
  }, [selectedTaskId]);

  const stopTask = (taskId: number) => {
    void api
      .cancelTask(taskId)
      .then(() => loadDetail(taskId))
      .catch((err) => setDetailError(err instanceof Error ? err.message : 'Failed to cancel task'));
  };

  const retryTask = (taskId: number) => {
    void api
      .retryTask(taskId)
      .then(() => loadDetail(taskId))
      .catch((err) => setDetailError(err instanceof Error ? err.message : 'Failed to retry task'));
  };

  return (
    <>
      <h2>Task Queue</h2>
      <p className="section-desc">Choose a task to inspect its full execution trace and lifecycle events.</p>

      <div className="tasks-layout">
        <section className="tasks-sidebar card">
          <div className="card-title">Queued Tasks</div>
          <div className="tasks-sidebar-inner">
            {tasks.map((task) => (
              <Link
                key={task.id}
                className={`task-item ${task.id === selectedTaskId ? 'active' : ''}`}
                to={`/tasks/${task.id}`}
              >
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-tertiary)' }}>{task.id}</div>
                <div>
                  <span className="pill" style={{ color: statusColor(task.status) }}>
                    <span className="pill-dot" />
                    {task.status}
                  </span>
                </div>
                <div className="task-item-meta">
                  <span>{task.provider}</span>
                  {task.is_proactive && <span className="pill mini-pill">proactive</span>}
                  <span>{task.created_at}</span>
                </div>
              </Link>
            ))}
            {tasks.length === 0 && (
              <div className="tasks-sidebar-empty">No tasks available.</div>
            )}
          </div>
        </section>

        <section className="tasks-main card">
          <div className="card-title">Trace Inspector</div>

          {!detailTask ? (
            <div className="task-detail-empty">Select a task from the left to load its trace.</div>
          ) : (
            <>
              <div className="task-detail-actions">
                <button
                  className="btn btn-sm btn-danger"
                  onClick={() => stopTask(detailTask.id)}
                  disabled={!['queued', 'running'].includes(detailTask.status)}
                >
                  Stop
                </button>
                <button
                  className="btn btn-sm"
                  onClick={() => retryTask(detailTask.id)}
                  disabled={!['failed', 'cancelled'].includes(detailTask.status)}
                >
                  Retry
                </button>
              </div>

              {detailError && <div className="task-error">Error: {detailError}</div>}

              <div className="kv-grid task-summary-grid">
                <div className="kv-item">
                  <div className="kv-label">Status</div>
                  <div className="kv-value">
                    <span className="pill" style={{ color: statusColor(detailTask.status) }}>
                      <span className="pill-dot" />
                      {detailTask.status}
                    </span>
                  </div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Provider</div>
                  <div className="kv-value">{detailTask.provider}</div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Channel</div>
                  <div className="kv-value">{detailTask.channel_id || '—'}</div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Thread</div>
                  <div className="kv-value">{detailTask.thread_ts || '—'}</div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Started</div>
                  <div className="kv-value">{detailTask.started_at || '—'}</div>
                </div>
                <div className="kv-item">
                  <div className="kv-label">Finished</div>
                  <div className="kv-value">{detailTask.finished_at || '—'}</div>
                </div>
              </div>

              <div className="kv-grid task-summary-grid">
                <div className="kv-item task-large-value">
                  <div className="kv-label">Prompt</div>
                  <pre className="trace-code">{detailTask.prompt_text || '—'}</pre>
                </div>
                <div className="kv-item task-large-value">
                  <div className="kv-label">Result</div>
                  <pre className="trace-code" style={{ color: detailTask.error_text ? 'var(--red)' : undefined }}>
                    {detailTask.result_text || detailTask.error_text || '—'}
                  </pre>
                </div>
              </div>

              <div className="trace-panel">
                <div className="card-title" style={{ marginBottom: 8 }}>Execution Trace</div>
                {traces.length === 0 ? (
                  <div className="task-detail-empty">No trace events yet.</div>
                ) : (
                  <div className="trace-list">
                    {traces.map((trace) => (
                      <article key={trace.id} className={`trace-item trace-${trace.level.toLowerCase()}`}>
                        <div className="trace-item-header">
                          <span className="pill" style={{ color: statusColor(trace.level) }}>
                            <span className="pill-dot" />
                            {trace.event_type}
                          </span>
                          <span className="trace-time">{trace.created_at}</span>
                        </div>
                        <div className="trace-message">{trace.message}</div>
                        {trace.details && <pre className="trace-code">{trace.details}</pre>}
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      </div>

      {listError && <div className="card" style={{ color: 'var(--red)', marginTop: 12 }}>Error: {listError}</div>}
    </>
  );
}
