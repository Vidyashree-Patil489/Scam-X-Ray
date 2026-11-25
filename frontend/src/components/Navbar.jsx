import { useLocation, useNavigate } from 'react-router-dom';
import { ZapIcon } from './Icons';

const ROUTE_TITLES = {
  '/dashboard': 'Threat Intelligence Dashboard',
  '/scam-detection': 'Scam Detection Suite',
  '/analyzer': 'Scam Detection Suite',
  '/results': 'Analysis Report',
  '/ai-image-detection': 'AI Image Detection & Forensics',
  '/security-awareness': 'Security Awareness & Prevention',
  '/settings': 'Platform Settings',
  '/about': 'About ScamXRay',
};

export default function Navbar({ mobileOpen, setMobileOpen }) {
  const location = useLocation();
  const navigate = useNavigate();

  const currentTitle = ROUTE_TITLES[location.pathname] || 'Digital Threat Intelligence';

  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        height: 68,
        background: 'rgba(255, 255, 255, 0.92)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(99, 102, 241, 0.14)',
        padding: '0 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        transition: 'all 0.25s ease',
      }}
    >
      {/* Left section: Hamburger (mobile) + Page Title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="navbar-mobile-toggle"
          title="Toggle Navigation"
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            border: '1px solid rgba(99, 102, 241, 0.18)',
            background: '#ffffff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            fontSize: 16,
            color: '#475569',
            boxShadow: '0 1px 4px rgba(99, 102, 241, 0.05)',
          }}
        >
          ☰
        </button>

        <div>
          <h1
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 'clamp(15px, 2vw, 18px)',
              fontWeight: 700,
              color: '#0f172a',
              letterSpacing: '-0.02em',
              margin: 0,
              lineHeight: 1.2,
            }}
          >
            {currentTitle}
          </h1>
          <span
            style={{
              fontSize: 11,
              color: '#94a3b8',
              fontWeight: 500,
              display: 'inline-block',
              fontFamily: 'var(--font-body)',
            }}
          >
            AI-Powered Digital Threat Intelligence
          </span>
        </div>
      </div>

      {/* Right section: System Status + Quick Scan Button */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div
          className="navbar-status-pill"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 7,
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.25)',
            borderRadius: 20,
            padding: '5px 12px',
            fontSize: 11.5,
            fontWeight: 600,
            color: '#059669',
            fontFamily: 'var(--font-body)',
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: '#10b981',
              boxShadow: '0 0 6px rgba(16, 185, 129, 0.6)',
            }}
          />
          Engine Ready
        </div>

        <button
          className="btn-primary"
          onClick={() => navigate('/scam-detection')}
          style={{
            padding: '8px 18px',
            fontSize: 12.5,
            borderRadius: 30,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <ZapIcon size={14} color="#ffffff" />
          <span>Quick Scan</span>
        </button>
      </div>
    </header>
  );
}
