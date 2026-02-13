import { NavLink, Outlet, useLocation } from 'react-router-dom';

type GlyphName =
  | 'queue'
  | 'status'
  | 'diagnostics'
  | 'cron'
  | 'guardrails'
  | 'approvals'
  | 'context'
  | 'memory'
  | 'settings'
  | 'auth';

interface NavItem {
  to: string;
  label: string;
  glyph: GlyphName;
}

const NAV_SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: 'Workspace',
    items: [
      { to: '/tasks', label: 'Queue', glyph: 'queue' },
      { to: '/status', label: 'Status', glyph: 'status' },
      { to: '/diagnostics', label: 'Diagnostics', glyph: 'diagnostics' },
    ],
  },
  {
    title: 'Automation',
    items: [
      { to: '/cron', label: 'Cron Jobs', glyph: 'cron' },
      { to: '/guardrails', label: 'Guardrails', glyph: 'guardrails' },
      { to: '/approvals', label: 'Approvals', glyph: 'approvals' },
    ],
  },
  {
    title: 'Knowledge',
    items: [
      { to: '/context', label: 'Context', glyph: 'context' },
      { to: '/memory', label: 'Memory', glyph: 'memory' },
    ],
  },
  {
    title: 'System',
    items: [
      { to: '/settings', label: 'Settings', glyph: 'settings' },
      { to: '/auth', label: 'Auth', glyph: 'auth' },
    ],
  },
];

const ALL_ITEMS = NAV_SECTIONS.flatMap((section) => section.items);

function isRouteActive(pathname: string, to: string): boolean {
  return pathname === to || pathname.startsWith(`${to}/`);
}

function titleForPath(pathname: string): string {
  const match = ALL_ITEMS.find((item) => isRouteActive(pathname, item.to));
  return match?.label ?? 'FastClaw';
}

function NavGlyph({ name }: { name: GlyphName }) {
  switch (name) {
    case 'queue':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M2.5 3.5h11M2.5 8h11M2.5 12.5h11" />
        </svg>
      );
    case 'status':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M3 12V8M7 12V5M11 12V3M14 12V9" />
        </svg>
      );
    case 'diagnostics':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M8 2.5v2.25M8 11.25V13.5M2.5 8h2.25M11.25 8h2.25M3.9 3.9l1.6 1.6M10.5 10.5l1.6 1.6M12.1 3.9l-1.6 1.6M5.5 10.5l-1.6 1.6" />
          <circle cx="8" cy="8" r="2.3" />
        </svg>
      );
    case 'cron':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <circle cx="8" cy="8" r="5.5" />
          <path d="M8 4.5V8l2.5 1.5" />
        </svg>
      );
    case 'guardrails':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M8 2.5l4.5 1.6v3.4c0 2.4-1.2 4.2-4.5 6-3.3-1.8-4.5-3.6-4.5-6V4.1z" />
        </svg>
      );
    case 'approvals':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M2.5 8l3 3 8-8" />
        </svg>
      );
    case 'context':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M2.5 4.5h4l1.2 1.5h5.8v5.5a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1z" />
        </svg>
      );
    case 'memory':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <rect x="3" y="3" width="10" height="10" rx="2" />
          <path d="M5.5 6h5M5.5 8h5M5.5 10h3.5" />
        </svg>
      );
    case 'settings':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <path d="M8 2.5l1 .4.9-.5 1.2 1.2-.5.9.4 1 .9.4v1.7l-.9.4-.4 1 .5.9-1.2 1.2-.9-.5-1 .4-.4.9H7l-.4-.9-1-.4-.9.5-1.2-1.2.5-.9-.4-1-.9-.4V6.2l.9-.4.4-1-.5-.9 1.2-1.2.9.5 1-.4L7 2.5z" />
          <circle cx="8" cy="8" r="1.9" />
        </svg>
      );
    case 'auth':
      return (
        <svg viewBox="0 0 16 16" aria-hidden="true">
          <rect x="3" y="7" width="10" height="6" rx="1.4" />
          <path d="M5.5 7V5.5A2.5 2.5 0 0 1 8 3a2.5 2.5 0 0 1 2.5 2.5V7" />
        </svg>
      );
    default:
      return null;
  }
}

export function Layout() {
  const location = useLocation();
  const currentTitle = titleForPath(location.pathname);

  return (
    <div className="linear-shell">
      <aside className="linear-sidebar">
        <div className="sidebar-header">
          <div className="workspace-mark">FC</div>
          <div className="workspace-meta">
            <div className="workspace-name">FastClaw</div>
            <div className="workspace-subtitle">Operations Console</div>
          </div>
        </div>

        <NavLink to="/tasks" className="sidebar-primary-link">
          Open Queue
        </NavLink>

        <nav className="sidebar-sections" aria-label="Main navigation">
          {NAV_SECTIONS.map((section) => (
            <section key={section.title} className="sidebar-section">
              <h2 className="sidebar-section-title">{section.title}</h2>
              <div className="sidebar-links">
                {section.items.map((item) => {
                  const active = isRouteActive(location.pathname, item.to);
                  return (
                    <NavLink key={item.to} to={item.to} className={`sidebar-link ${active ? 'active' : ''}`}>
                      <span className="nav-glyph">
                        <NavGlyph name={item.glyph} />
                      </span>
                      <span className="nav-label">{item.label}</span>
                    </NavLink>
                  );
                })}
              </div>
            </section>
          ))}
        </nav>

        <div className="sidebar-whats-new">
          <p className="sidebar-whats-new-title">What&apos;s new</p>
          <p className="sidebar-whats-new-body">
            Linear-inspired shell for monitoring tasks, approvals, and agent activity.
          </p>
        </div>
      </aside>

      <section className="linear-content">
        <header className="linear-topbar">
          <div className="topbar-crumbs">
            <span className="topbar-workspace">FastClaw</span>
            <span className="topbar-sep">/</span>
            <span className="topbar-current">{currentTitle}</span>
          </div>
          <div className="topbar-actions">
            <span className="topbar-chip">Admin</span>
            <button type="button" className="topbar-button">Display</button>
          </div>
        </header>
        <main className="app-main">
          <Outlet />
        </main>
      </section>
    </div>
  );
}
