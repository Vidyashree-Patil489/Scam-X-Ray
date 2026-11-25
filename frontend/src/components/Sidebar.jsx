import { NavLink } from 'react-router-dom';
import {
  ShieldIcon,
  MessageSquareIcon,
  EyeScanIcon,
  LockIcon
} from './Icons';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: ShieldIcon },
  { path: '/scam-detection', label: 'Scam Detection', icon: MessageSquareIcon },
  { path: '/ai-image-detection', label: 'AI Image Detection', icon: EyeScanIcon },
  { path: '/security-awareness', label: 'Security Awareness', icon: ShieldIcon },
  { path: '/settings', label: 'Settings', icon: LockIcon },
];

export default function Sidebar({ collapsed, setCollapsed, mobileOpen, setMobileOpen }) {
  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.45)',
            backdropFilter: 'blur(4px)',
            WebkitBackdropFilter: 'blur(4px)',
            zIndex: 140,
            transition: 'opacity 0.25s ease',
          }}
        />
      )}

      {/* Sidebar container with stronger visual contrast & crisp right shadow */}
      <aside
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          bottom: 0,
          width: collapsed ? 76 : 256,
          background: '#ffffff',
          borderRight: '1px solid rgba(99, 102, 241, 0.16)',
          zIndex: 150,
          display: 'flex',
          flexDirection: 'column',
          transition: 'width 0.25s cubic-bezier(0.4, 0, 0.2, 1), transform 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
          transform: mobileOpen ? 'translateX(0)' : undefined,
          boxShadow: mobileOpen
            ? '0 12px 48px rgba(15, 23, 42, 0.25)'
            : '4px 0 24px rgba(99, 102, 241, 0.05)',
        }}
        className={`sidebar-root ${mobileOpen ? 'mobile-open' : ''}`}
      >
        {/* Brand header */}
        <div
          style={{
            height: 68,
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'space-between',
            padding: collapsed ? '0 12px' : '0 20px',
            borderBottom: '1px solid rgba(99, 102, 241, 0.1)',
            background: 'linear-gradient(180deg, #ffffff 0%, #faf9ff 100%)',
          }}
        >
          <NavLink
            to="/"
            onClick={() => setMobileOpen(false)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              textDecoration: 'none',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'linear-gradient(135deg, #6366f1, #764ba2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#ffffff',
                boxShadow: '0 4px 14px rgba(99, 102, 241, 0.3)',
                flexShrink: 0,
              }}
            >
              <ShieldIcon size={19} color="#ffffff" />
            </div>
            {!collapsed && (
              <div style={{ whiteSpace: 'nowrap' }}>
                <span
                  style={{
                    fontFamily: 'var(--font-heading)',
                    fontWeight: 800,
                    fontSize: 17,
                    letterSpacing: '-0.02em',
                    display: 'block',
                    lineHeight: 1.15,
                  }}
                >
                  <span style={{ color: '#6366f1' }}>Scam</span>
                  <span style={{ color: '#0f172a' }}>XRay</span>
                </span>
                <span
                  style={{
                    display: 'block',
                    fontSize: 10,
                    fontWeight: 700,
                    color: '#94a3b8',
                    letterSpacing: '0.07em',
                    textTransform: 'uppercase',
                    marginTop: 2,
                    fontFamily: 'var(--font-body)',
                  }}
                >
                  Threat Intelligence
                </span>
              </div>
            )}
          </NavLink>

          {/* Desktop collapse toggle button */}
          {!collapsed && (
            <button
              onClick={() => setCollapsed(!collapsed)}
              title="Collapse sidebar"
              className="sidebar-collapse-btn"
              style={{
                width: 28,
                height: 28,
                borderRadius: 8,
                border: '1px solid rgba(99, 102, 241, 0.16)',
                background: '#f8f7ff',
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: 11,
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#ede9fe';
                e.currentTarget.style.color = '#6366f1';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = '#f8f7ff';
                e.currentTarget.style.color = '#64748b';
              }}
            >
              ◀
            </button>
          )}
        </div>

        {/* Expand toggle icon button when collapsed */}
        {collapsed && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '10px 0 2px' }}>
            <button
              onClick={() => setCollapsed(false)}
              title="Expand sidebar"
              className="sidebar-collapse-btn"
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                border: '1px solid rgba(99, 102, 241, 0.16)',
                background: '#f8f7ff',
                color: '#64748b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: 11,
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#ede9fe';
                e.currentTarget.style.color = '#6366f1';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = '#f8f7ff';
                e.currentTarget.style.color = '#64748b';
              }}
            >
              ▶
            </button>
          </div>
        )}

        {/* Navigation items list */}
        <nav
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: collapsed ? '10px 8px' : '14px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}
        >
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={() => setMobileOpen(false)}
                title={collapsed ? item.label : undefined}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: collapsed ? '11px 0' : '9px 12px',
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  borderRadius: 10,
                  textDecoration: 'none',
                  fontSize: 13.5,
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? '#6366f1' : '#475569',
                  background: isActive ? '#ede9fe' : 'transparent',
                  border: isActive ? '1px solid rgba(99, 102, 241, 0.2)' : '1px solid transparent',
                  boxShadow: isActive ? '0 2px 8px rgba(99, 102, 241, 0.08)' : 'none',
                  transition: 'all 0.18s ease',
                  position: 'relative',
                })}
                className="sidebar-nav-item"
              >
                {({ isActive }) => (
                  <>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: isActive ? '#6366f1' : '#64748b',
                        transition: 'color 0.18s ease',
                      }}
                    >
                      <Icon size={18} color="currentColor" />
                    </span>
                    {!collapsed && (
                      <span
                        style={{
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          flex: 1,
                        }}
                      >
                        {item.label}
                      </span>
                    )}
                    {/* Active pip on expanded desktop */}
                    {isActive && !collapsed && (
                      <span
                        style={{
                          width: 5,
                          height: 5,
                          borderRadius: '50%',
                          background: '#6366f1',
                          display: 'inline-block',
                          boxShadow: '0 0 6px #6366f1',
                        }}
                      />
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Sidebar footer status area */}
        <div
          style={{
            padding: collapsed ? '12px 6px' : '14px 16px',
            borderTop: '1px solid rgba(99, 102, 241, 0.1)',
            background: '#faf9ff',
          }}
        >
          {collapsed ? (
            <div style={{ textAlign: 'center', padding: '4px 0' }} title="Multi-Layer Engine Online">
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: '#10b981',
                  display: 'inline-block',
                  boxShadow: '0 0 8px rgba(16, 185, 129, 0.6)',
                }}
              />
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                background: '#ffffff',
                padding: '9px 12px',
                borderRadius: 10,
                border: '1px solid rgba(99, 102, 241, 0.12)',
              }}
            >
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: '#10b981',
                  display: 'inline-block',
                  boxShadow: '0 0 8px rgba(16, 185, 129, 0.6)',
                }}
              />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#0f172a' }}>Protection Active</div>
                <div style={{ fontSize: 10, color: '#94a3b8' }}>Multi-Layer Engine Online</div>
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
