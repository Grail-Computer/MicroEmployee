import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, type TaskData, type TaskListItemData, type TaskTraceData } from '../lib/api';

type TranscriptRole = 'user' | 'assistant' | 'tool' | 'system';

interface TranscriptMessage {
  id: string;
  role: TranscriptRole;
  label: string;
  body: string;
  timestamp: string;
  eventType?: string;
  status?: string;
  details?: string;
}

const MAX_TRACE_DETAIL_CHARS = 5000;
const MAX_COMMAND_OUTPUT_CHARS = 7000;
const STATUS_FILTER_ORDER = ['running', 'queued', 'succeeded', 'failed', 'cancelled'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function clipText(value: string, maxChars = MAX_TRACE_DETAIL_CHARS): string {
  if (value.length <= maxChars) return value;
  const hidden = value.length - maxChars;
  return `${value.slice(0, maxChars)}\n… (${hidden} chars hidden)`;
}

function safeParseJson(details: string): unknown | undefined {
  const trimmed = details.trim();
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function prettyJson(value: unknown): string {
  return clipText(JSON.stringify(value, null, 2));
}

function buildTraceMessage(trace: TaskTraceData): TranscriptMessage | null {
  if (trace.event_type === 'agent.delta') return null;

  const detailText = trace.details?.trim() ?? '';
  const parsed = safeParseJson(detailText);

  if (isRecord(parsed)) {
    const itemType = readString(parsed.type);

    if (itemType === 'agentMessage') {
      return null;
    }

    if (itemType === 'commandExecution') {
      const command = readString(parsed.command);
      const status = readString(parsed.status);
      const cwd = readString(parsed.cwd);
      const exitCode = typeof parsed.exitCode === 'number' ? `exit ${parsed.exitCode}` : undefined;
      const output = readString(parsed.aggregatedOutput);
      const statusLine = [status, exitCode, cwd ? `cwd ${cwd}` : undefined].filter(Boolean).join(' · ');

      return {
        id: `trace-${trace.id}`,
        role: 'tool',
        label: 'Tool',
        body: command ? `$ ${command}` : trace.message || 'Command execution',
        timestamp: trace.created_at,
        eventType: trace.event_type,
        status: statusLine || undefined,
        details: output ? clipText(output, MAX_COMMAND_OUTPUT_CHARS) : prettyJson(parsed),
      };
    }

    if (itemType) {
      const isReasoning = itemType.toLowerCase().includes('reason');
      return {
        id: `trace-${trace.id}`,
        role: isReasoning ? 'assistant' : 'tool',
        label: isReasoning ? 'Assistant reasoning' : `Tool · ${itemType}`,
        body: trace.message || itemType,
        timestamp: trace.created_at,
        eventType: trace.event_type,
        status: trace.level,
        details: prettyJson(parsed),
      };
    }
  }

  const label =
    trace.event_type === 'turn.start'
      ? 'Run started'
      : trace.event_type === 'turn.completed'
        ? 'Run completed'
        : trace.event_type.startsWith('approval.')
          ? 'Approval'
          : 'System';

  const details = detailText && detailText !== trace.message ? clipText(detailText) : undefined;

  return {
    id: `trace-${trace.id}`,
    role: 'system',
    label,
    body: trace.message || trace.event_type,
    timestamp: trace.created_at,
    eventType: trace.event_type,
    status: trace.level,
    details,
  };
}

function roleGlyph(role: TranscriptRole): string {
  if (role === 'user') return 'U';
  if (role === 'assistant') return 'A';
  if (role === 'tool') return 'T';
  return 'S';
}

function formatStatusLabel(status: string): string {
  return status
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

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
  const [statusFilter, setStatusFilter] = useState('all');
  const [listError, setListError] = useState('');
  const [detailError, setDetailError] = useState('');

  const statusColor = (s: string) => {
    if (s === 'succeeded' || s === 'completed' || s === 'done') return 'var(--green)';
    if (s === 'failed' || s === 'cancelled' || s === 'error') return 'var(--red)';
    if (s === 'running') return 'var(--accent)';
    if (s === 'info') return 'var(--accent)';
    if (s === 'debug') return 'var(--text-secondary)';
    if (s === 'queued') return 'var(--yellow)';
    if (s === 'warning') return 'var(--yellow)';
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

  const filterOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const task of tasks) {
      counts.set(task.status, (counts.get(task.status) ?? 0) + 1);
    }

    const discoveredStatuses = Array.from(counts.keys()).sort((a, b) => a.localeCompare(b));
    const orderedStatuses = [
      ...STATUS_FILTER_ORDER.filter((status) => counts.has(status)),
      ...discoveredStatuses.filter((status) => !STATUS_FILTER_ORDER.includes(status as (typeof STATUS_FILTER_ORDER)[number])),
    ];

    return [
      { value: 'all', label: 'All', count: tasks.length },
      ...orderedStatuses.map((status) => ({
        value: status,
        label: formatStatusLabel(status),
        count: counts.get(status) ?? 0,
      })),
    ];
  }, [tasks]);

  useEffect(() => {
    if (statusFilter !== 'all' && !tasks.some((task) => task.status === statusFilter)) {
      setStatusFilter('all');
    }
  }, [statusFilter, tasks]);

  const visibleTasks = useMemo(
    () => (statusFilter === 'all' ? tasks : tasks.filter((task) => task.status === statusFilter)),
    [statusFilter, tasks],
  );

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

  const transcript = useMemo<TranscriptMessage[]>(() => {
    if (!detailTask) return [];

    const messages: TranscriptMessage[] = [
      {
        id: `task-${detailTask.id}-prompt`,
        role: 'user',
        label: 'User',
        body: detailTask.prompt_text?.trim() || 'No prompt text.',
        timestamp: detailTask.created_at,
      },
    ];

    for (const trace of traces) {
      const entry = buildTraceMessage(trace);
      if (entry) messages.push(entry);
    }

    if (detailTask.result_text?.trim()) {
      messages.push({
        id: `task-${detailTask.id}-result`,
        role: 'assistant',
        label: 'Assistant',
        body: detailTask.result_text.trim(),
        timestamp: detailTask.finished_at || detailTask.created_at,
      });
    }

    if (detailTask.error_text?.trim()) {
      messages.push({
        id: `task-${detailTask.id}-error`,
        role: 'system',
        label: 'Run error',
        body: detailTask.error_text.trim(),
        timestamp: detailTask.finished_at || detailTask.created_at,
        status: 'error',
      });
    }

    return messages;
  }, [detailTask, traces]);

  return (
    <>
      <h2>Task Queue</h2>
      <p className="section-desc">Choose a task to inspect its full execution trace and lifecycle events.</p>

      <div className="tasks-toolbar">
        <div className="segmented-control" role="tablist" aria-label="Filter tasks by status">
          {filterOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              role="tab"
              aria-selected={statusFilter === option.value}
              className={`segment-btn ${statusFilter === option.value ? 'active' : ''}`}
              onClick={() => setStatusFilter(option.value)}
            >
              <span>{option.label}</span>
              <span className="segment-count">{option.count}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="tasks-layout">
        <section className="tasks-sidebar card">
          <div className="card-title">Tasks</div>
          <div className="tasks-sidebar-inner">
            {visibleTasks.map((task) => (
              <Link
                key={task.id}
                className={`task-item ${task.id === selectedTaskId ? 'active' : ''}`}
                to={`/tasks/${task.id}`}
              >
                <div className="task-item-head">
                  <span className="task-item-id">#{task.id}</span>
                  <span className="pill" style={{ color: statusColor(task.status) }}>
                    <span className="pill-dot" />
                    {formatStatusLabel(task.status)}
                  </span>
                </div>
                <div className="task-item-title">{task.prompt_text?.trim() || 'No prompt text.'}</div>
                <div className="task-item-meta">
                  <span>{task.provider}</span>
                  {task.is_proactive && <span className="pill mini-pill">proactive</span>}
                  <span>{task.created_at}</span>
                </div>
              </Link>
            ))}
            {visibleTasks.length === 0 && (
              <div className="tasks-sidebar-empty">
                {tasks.length === 0 ? 'No tasks available.' : `No tasks in ${formatStatusLabel(statusFilter)}.`}
              </div>
            )}
          </div>
        </section>

        <section className="tasks-main card">
          <div className="card-title">
            {detailTask ? `Task #${detailTask.id}` : 'Trace Inspector'}
          </div>

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
                <div className="card-title" style={{ marginBottom: 8 }}>Chat Transcript</div>
                <p className="trace-subtitle">Read-only AI SDK-style timeline of user, tool, system, and assistant messages.</p>
                {transcript.length === 0 ? (
                  <div className="task-detail-empty">No trace events yet.</div>
                ) : (
                  <div className="chat-transcript">
                    {transcript.map((message) => (
                      <article key={message.id} className={`chat-row role-${message.role}`}>
                        <div className={`chat-avatar role-${message.role}`}>{roleGlyph(message.role)}</div>
                        <div className="chat-bubble">
                          <div className="chat-meta">
                            <span className="chat-label">{message.label}</span>
                            {message.eventType && <span className="chat-event">{message.eventType}</span>}
                            {message.status && (
                              <span className="pill" style={{ color: statusColor(message.status) }}>
                                <span className="pill-dot" />
                                {message.status}
                              </span>
                            )}
                            <span className="chat-time">{message.timestamp}</span>
                          </div>
                          <div className="chat-body">{message.body}</div>
                          {message.details && <pre className="chat-code">{message.details}</pre>}
                        </div>
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
