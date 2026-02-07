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
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/admin/status" replace />} />
        <Route path="/admin" element={<Navigate to="/admin/status" replace />} />
        <Route path="/admin/status" element={<StatusPage />} />
        <Route path="/admin/settings" element={<SettingsPage />} />
        <Route path="/admin/tasks" element={<TasksPage />} />
        <Route path="/admin/cron" element={<CronPage />} />
        <Route path="/admin/guardrails" element={<GuardrailsPage />} />
        <Route path="/admin/approvals" element={<ApprovalsPage />} />
        <Route path="/admin/memory" element={<MemoryPage />} />
        <Route path="/admin/context/*" element={<ContextPage />} />
        <Route path="/admin/auth" element={<AuthPage />} />
        <Route path="/admin/diagnostics" element={<DiagnosticsPage />} />
      </Routes>
    </Layout>
  );
}
