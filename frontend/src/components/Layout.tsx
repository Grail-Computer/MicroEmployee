import { NavLink, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

const NAV_ITEMS = [
  { to: '/status', label: 'Status' },
  { to: '/settings', label: 'Settings' },
  { to: '/cron', label: 'Cron' },
  { to: '/guardrails', label: 'Guardrails' },
  { to: '/approvals', label: 'Approvals' },
  { to: '/memory', label: 'Memory' },
  { to: '/context', label: 'Context' },
  { to: '/auth', label: 'Auth' },
  { to: '/tasks', label: 'Queue' },
  { to: '/diagnostics', label: 'Diagnostics' },
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
