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
        <Route path="/" element={<Navigate to="/status" replace />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/tasks" element={<TasksPage />} />
        <Route path="/cron" element={<CronPage />} />
        <Route path="/guardrails" element={<GuardrailsPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/memory" element={<MemoryPage />} />
        <Route path="/context/*" element={<ContextPage />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/diagnostics" element={<DiagnosticsPage />} />
      </Routes>
    </Layout>
  );
}
