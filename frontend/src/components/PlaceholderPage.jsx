import { useNavigate } from 'react-router-dom';

export default function PlaceholderPage({
  title = 'Module Coming Soon',
  subtitle = 'This threat intelligence tool is scheduled for implementation in upcoming stages.',
  icon = '🛠️',
  badge = 'Stage Roadmap',
}) {
  const navigate = useNavigate();

  return (
    <div className="fade-up" style={{ maxWidth: 860, margin: '20px auto 0' }}>
      <div
        className="card"
        style={{
          padding: '48px 32px',
          textAlign: 'center',
          border: '1px solid rgba(99, 102, 241, 0.15)',
        }}
      >
        <div
          style={{
            display: 'inline-block',
            background: 'linear-gradient(135deg, rgba(102, 126, 234, 0.15), rgba(118, 75, 162, 0.15))',
            color: '#667eea',
            fontSize: 11,
            fontWeight: 800,
            padding: '5px 14px',
            borderRadius: 20,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: 16,
          }}
        >
          {badge}
        </div>

        <div style={{ fontSize: 48, marginBottom: 16 }}>{icon}</div>

        <h1
          style={{
            fontSize: 'clamp(24px, 3vw, 32px)',
            fontWeight: 900,
            color: '#0f172a',
            marginBottom: 12,
            letterSpacing: '-0.02em',
          }}
        >
          {title}
        </h1>

        <p
          style={{
            fontSize: 15,
            color: '#64748b',
            maxWidth: 580,
            margin: '0 auto 28px',
            lineHeight: 1.7,
          }}
        >
          {subtitle}
        </p>

        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            onClick={() => navigate('/scam-detection')}
            style={{ fontSize: 14 }}
          >
            🛡️ Try Scam Detection Now
          </button>
          <button
            onClick={() => navigate('/')}
            style={{
              background: '#ffffff',
              color: '#475569',
              border: '1.5px solid rgba(99, 102, 241, 0.2)',
              borderRadius: 50,
              padding: '12px 24px',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
              fontFamily: 'Inter, sans-serif',
              transition: 'all 0.2s',
            }}
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
