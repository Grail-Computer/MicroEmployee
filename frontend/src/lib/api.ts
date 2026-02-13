const BASE = '/api/admin';

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...opts?.headers,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
  // Status
  getStatus: () => request<StatusData>('/status'),

  // Settings
  getSettings: () => request<SettingsData>('/settings'),
  saveSettings: (data: Partial<SettingsData>) =>
    request<{ ok: boolean }>('/settings', { method: 'POST', body: JSON.stringify(data) }),

  // Secrets
  setSecret: (key: string, value: string) =>
    request<{ ok: boolean }>(`/secrets/${key}`, { method: 'POST', body: JSON.stringify({ value }) }),
  deleteSecret: (key: string) =>
    request<{ ok: boolean }>(`/secrets/${key}`, { method: 'DELETE' }),

  // Tasks
  getTasks: () => request<{ tasks: TaskListItemData[] }>('/tasks'),
  getTask: (id: number) => request<{ task: TaskData; traces: TaskTraceData[] }>(`/tasks/${id}`),
  cancelTask: (id: number) => request<{ ok: boolean }>(`/tasks/${id}/cancel`, { method: 'POST' }),
  retryTask: (id: number) => request<{ ok: boolean }>(`/tasks/${id}/retry`, { method: 'POST' }),

  // Memory
  getMemory: () => request<{ sessions: SessionData[] }>('/memory'),
  clearMemory: (key: string) =>
    request<{ ok: boolean }>('/memory/clear', { method: 'POST', body: JSON.stringify({ key }) }),

  // Context
  getContext: () => request<{ files: ContextFileData[] }>('/context'),
  getContextFile: (path: string) =>
    request<{ content: string; bytes: number }>(`/context/file?path=${encodeURIComponent(path)}`),
  saveContextFile: (path: string, content: string) =>
    request<{ ok: boolean }>('/context/file', { method: 'POST', body: JSON.stringify({ path, content }) }),

  // Cron
  getCron: () => request<CronData>('/cron'),
  addCronJob: (job: CronJobInput) =>
    request<{ ok: boolean }>('/cron/add', { method: 'POST', body: JSON.stringify(job) }),
  deleteCronJob: (id: string) => request<{ ok: boolean }>(`/cron/${id}/delete`, { method: 'POST' }),
  enableCronJob: (id: string) => request<{ ok: boolean }>(`/cron/${id}/enable`, { method: 'POST' }),
  disableCronJob: (id: string) => request<{ ok: boolean }>(`/cron/${id}/disable`, { method: 'POST' }),

  // Guardrails
  getGuardrails: () => request<{ rules: GuardrailData[] }>('/guardrails'),
  addGuardrail: (rule: GuardrailInput) =>
    request<{ ok: boolean }>('/guardrails/add', { method: 'POST', body: JSON.stringify(rule) }),
  deleteGuardrail: (id: string) => request<{ ok: boolean }>(`/guardrails/${id}/delete`, { method: 'POST' }),
  enableGuardrail: (id: string) => request<{ ok: boolean }>(`/guardrails/${id}/enable`, { method: 'POST' }),
  disableGuardrail: (id: string) => request<{ ok: boolean }>(`/guardrails/${id}/disable`, { method: 'POST' }),

  // Approvals
  getApprovals: () => request<{ approvals: ApprovalData[] }>('/approvals'),
  approveApproval: (id: string) => request<{ ok: boolean }>(`/approvals/${id}/approve`, { method: 'POST' }),
  alwaysApproval: (id: string) => request<{ ok: boolean }>(`/approvals/${id}/always`, { method: 'POST' }),
  denyApproval: (id: string) => request<{ ok: boolean }>(`/approvals/${id}/deny`, { method: 'POST' }),

  // Auth
  getAuth: () => request<AuthData>('/auth'),
  startDeviceLogin: () => request<{ ok: boolean }>('/auth/device/start', { method: 'POST' }),
  cancelDeviceLogin: () => request<{ ok: boolean }>('/auth/device/cancel', { method: 'POST' }),
  authLogout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
  startGithubDeviceLogin: () => request<{ ok: boolean }>('/auth/github/device/start', { method: 'POST' }),
  cancelGithubDeviceLogin: () => request<{ ok: boolean }>('/auth/github/device/cancel', { method: 'POST' }),
  githubLogout: () => request<{ ok: boolean }>('/auth/github/logout', { method: 'POST' }),

  // Diagnostics
  getDiagnostics: () => request<DiagnosticsData>('/diagnostics'),
  runCodexTest: () => request<DiagnosticsData>('/diagnostics/codex', { method: 'POST' }),
};

// ── Types ──

export interface StatusData {
  slack_signing_secret_set: boolean;
  slack_bot_token_set: boolean;
  telegram_bot_token_set: boolean;
  telegram_webhook_secret_set: boolean;
  openai_api_key_set: boolean;
  master_key_set: boolean;
  queue_depth: number;
  permissions_mode: string;
  slack_events_url: string;
  slack_actions_url: string;
  telegram_webhook_url: string;
  worker_lock_owner: string;
  active_task_id: string;
  active_task_started_at: string;
  pending_approvals: number;
  guardrails_enabled: number;
}

export interface SettingsData {
  context_last_n: number;
  model: string;
  reasoning_effort: string;
  reasoning_summary: string;
  permissions_mode: string;
  slack_allow_from: string;
  slack_allow_channels: string;
  slack_proactive_enabled: boolean;
  slack_proactive_snippet: string;
  allow_telegram: boolean;
  telegram_allow_from: string;
  allow_slack_mcp: boolean;
  allow_web_mcp: boolean;
  extra_mcp_config: string;
  allow_context_writes: boolean;
  shell_network_access: boolean;
  allow_cron: boolean;
  auto_apply_cron_jobs: boolean;
  agent_name: string;
  role_description: string;
  command_approval_mode: string;
  auto_apply_guardrail_tighten: boolean;
  web_allow_domains: string;
  web_deny_domains: string;
  // Secret status flags
  master_key_set: boolean;
  openai_api_key_set: boolean;
  slack_signing_secret_set: boolean;
  slack_bot_token_set: boolean;
  telegram_bot_token_set: boolean;
  telegram_webhook_secret_set: boolean;
  brave_search_api_key_set: boolean;
}

export interface TaskListItemData {
  id: number;
  status: string;
  provider: string;
  is_proactive: boolean;
  channel_id: string;
  thread_ts: string;
  prompt_text: string;
  result_text: string;
  error_text: string;
  created_at: string;
  started_at: string;
  finished_at: string;
}

export interface TaskData extends TaskListItemData {
  workspace_id: string;
  conversation_key: string;
  event_ts: string;
  requested_by_user_id: string;
  files_json: string;
}

export interface TaskTraceData {
  id: number;
  event_type: string;
  level: string;
  message: string;
  details: string;
  created_at: string;
}

export interface SessionData {
  conversation_key: string;
  codex_thread_id: string;
  memory_summary: string;
  last_used_at: string;
}

export interface ContextFileData {
  path: string;
  bytes: number;
}

export interface CronData {
  cron_enabled: boolean;
  workspace_id: string;
  jobs: CronJobData[];
}

export interface CronJobData {
  id: string;
  enabled: boolean;
  name: string;
  mode: string;
  schedule: string;
  channel_id: string;
  thread_ts: string;
  prompt_text: string;
  next_run_at: string;
  last_run_at: string;
  last_status: string;
  last_error: string;
  created_at: string;
}

export interface CronJobInput {
  name: string;
  channel_id: string;
  thread_ts: string;
  prompt_text: string;
  schedule_kind: string;
  every_seconds?: number;
  cron_expr?: string;
}

export interface GuardrailData {
  id: string;
  enabled: boolean;
  kind: string;
  action: string;
  priority: string;
  name: string;
  pattern_kind: string;
  pattern: string;
  created_at: string;
}

export interface GuardrailInput {
  kind: string;
  action: string;
  priority: number;
  name: string;
  pattern_kind: string;
  pattern: string;
}

export interface ApprovalData {
  id: string;
  status: string;
  kind: string;
  decision: string;
  created_at: string;
  details: string;
}

export interface AuthData {
  openai_api_key_set: boolean;
  codex_auth_file_set: boolean;
  codex_auth_mode: string;
  device_login?: {
    status: string;
    verification_url: string;
    user_code: string;
    error_text: string;
    created_at: string;
  };
  github_client_id_set: boolean;
  github_token_set: boolean;
  github_device_login?: {
    status: string;
    verification_url: string;
    user_code: string;
    error_text: string;
    created_at: string;
  };
}

export interface DiagnosticsData {
  codex_result?: string;
  codex_error?: string;
}
