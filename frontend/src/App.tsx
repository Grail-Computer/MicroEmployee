import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { StatusPage } from './pages/StatusPage';
import { SettingsPage } from './pages/SettingsPage';
import { TasksPage } from './pages/TasksPage';
import { CronPage } from './pages/CronPage';
import { GuardrailsPage } from './pages/GuardrailsPage';
import { ApprovalsPage } from './pages/ApprovalsPage';
import { MemoryPage } from './pages/MemoryPage';
import { ContextPage } from './pages/ContextPage';
import { AuthPage } from './pages/AuthPage';
import { DiagnosticsPage } from './pages/DiagnosticsPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="tasks" replace />} />
        <Route path="status" element={<StatusPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="tasks" element={<TasksPage />} />
        <Route path="tasks/:id" element={<TasksPage />} />
        <Route path="cron" element={<CronPage />} />
        <Route path="guardrails" element={<GuardrailsPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="memory" element={<MemoryPage />} />
        <Route path="context/*" element={<ContextPage />} />
        <Route path="auth" element={<AuthPage />} />
        <Route path="diagnostics" element={<DiagnosticsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

function NotFoundPage() {
  return (
    <div className="card">
      <div className="card-title">Not found</div>
      <p className="section-desc" style={{ margin: 0 }}>
        No route matched this URL.
      </p>
    </div>
  );
}
