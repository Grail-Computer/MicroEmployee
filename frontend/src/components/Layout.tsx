import { NavLink, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

const NAV_ITEMS = [
  { to: '/admin/status', label: 'Status' },
  { to: '/admin/settings', label: 'Settings' },
  { to: '/admin/cron', label: 'Cron' },
  { to: '/admin/guardrails', label: 'Guardrails' },
  { to: '/admin/approvals', label: 'Approvals' },
  { to: '/admin/memory', label: 'Memory' },
  { to: '/admin/context', label: 'Context' },
  { to: '/admin/auth', label: 'Auth' },
  { to: '/admin/tasks', label: 'Queue' },
  { to: '/admin/diagnostics', label: 'Diagnostics' },
];

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <span className="app-brand">Grail</span>
        <nav className="app-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                isActive || location.pathname.startsWith(item.to) ? 'active' : ''
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
