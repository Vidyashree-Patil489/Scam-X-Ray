import { useNavigate } from 'react-router-dom';
import {
  ShieldIcon,
  MessageSquareIcon,
  EyeScanIcon,
  BinaryFileIcon,
  ScaleCheckIcon,
  ArrowRightIcon,
  LockIcon
} from '../components/Icons';

export default function Dashboard() {
  const navigate = useNavigate();

  // Current formatted date for contextual workspace header
  const currentDate = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });

  const PRIMARY_TOOLS = [
    {
      id: 'scam-detection',
      title: 'Scam Detection',
      tagline: 'Multi-Vector Communication Security',
      description: 'Analyse suspicious messages, recruitment offers, phishing emails, URLs and uploaded screenshots.',
      icon: MessageSquareIcon,
      accentColor: '#6366f1',
      badge: 'Message & URL Scanner',
      route: '/scam-detection',
      actionLabel: 'Open Scanner',
    },
    {
      id: 'ai-image-detection',
      title: 'AI Image Detection',
      tagline: 'Synthetic Generation Forensics',
      description: 'Examine images for visual indicators that may suggest AI-generated content.',
      icon: EyeScanIcon,
      accentColor: '#ec4899',
      badge: 'Visual Media Forensics',
      route: '/ai-image-detection',
      actionLabel: 'Open Scanner',
    },
    {
      id: 'steganography-scanner',
      title: 'Steganography Scanner',
      tagline: 'Hidden Information Forensics',
      description: 'Inspect image files for hidden data, suspicious metadata and unusual file structures.',
      icon: BinaryFileIcon,
      accentColor: '#06b6d4',
      badge: 'Binary Payload Inspection',
      route: '/steganography',
      actionLabel: 'Open Scanner',
    },
    {
      id: 'fact-checker',
      title: 'Fact Checker',
      tagline: 'Evidence-Based Claim Verification',
      description: 'Investigate claims using retrieved information and supporting evidence.',
      icon: ScaleCheckIcon,
      accentColor: '#10b981',
      badge: 'Evidence Verification',
      route: '/fact-checker',
      actionLabel: 'Open Scanner',
    },
  ];

  return (
    <div style={{ maxWidth: 1120, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 28 }}>
      {/* ─────────────────────────────────────────────────────────────
          1. DASHBOARD HEADER (Clean & Welcoming, zero oversized banner)
      ───────────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
          paddingBottom: 4,
        }}
      >
        <div>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              color: '#6366f1',
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              marginBottom: 6,
            }}
          >
            <ShieldIcon size={13} color="#6366f1" />
            <span>Threat Intelligence Console</span>
          </div>

          <h1
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 'clamp(22px, 2.5vw, 28px)',
              fontWeight: 800,
              color: '#0f172a',
              letterSpacing: '-0.025em',
              margin: '0 0 6px',
              lineHeight: 1.25,
            }}
          >
            Your Digital Security Workspace
          </h1>

          <p
            style={{
              fontSize: 14.5,
              color: '#64748b',
              margin: 0,
              maxWidth: 680,
              lineHeight: 1.6,
            }}
          >
            Choose an analysis tool to investigate suspicious content, examine digital media and verify information.
          </p>
        </div>

        {/* Clean Contextual Date Badge */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            background: '#ffffff',
            border: '1px solid rgba(99, 102, 241, 0.14)',
            padding: '7px 14px',
            borderRadius: 20,
            fontSize: 12,
            fontWeight: 600,
            color: '#475569',
            boxShadow: '0 1px 3px rgba(99, 102, 241, 0.04)',
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#6366f1' }} />
          <span>{currentDate}</span>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          2. FOUR MAIN ANALYSIS TOOLS (2 × 2 Desktop Grid)
      ───────────────────────────────────────────────────────────── */}
      <section>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
            gap: 20,
          }}
          className="dashboard-tools-grid"
        >
          {PRIMARY_TOOLS.map((tool) => {
            const IconComponent = tool.icon;
            return (
              <div
                key={tool.id}
                onClick={() => navigate(tool.route)}
                className="card hover-lift"
                style={{
                  padding: '26px 28px',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  background: '#ffffff',
                  border: '1px solid rgba(99, 102, 241, 0.14)',
                  borderRadius: 14,
                  position: 'relative',
                  transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                  minHeight: 220,
                }}
              >
                <div>
                  {/* Card Header: Icon + Purpose Label */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                    <div
                      style={{
                        width: 44,
                        height: 44,
                        borderRadius: 10,
                        background: `linear-gradient(135deg, ${tool.accentColor}14, ${tool.accentColor}26)`,
                        border: `1px solid ${tool.accentColor}30`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: tool.accentColor,
                      }}
                    >
                      <IconComponent size={22} color={tool.accentColor} />
                    </div>

                    <span
                      style={{
                        fontSize: 10.5,
                        fontWeight: 700,
                        color: tool.accentColor,
                        background: `${tool.accentColor}10`,
                        padding: '3px 10px',
                        borderRadius: 20,
                        letterSpacing: '0.03em',
                        border: `1px solid ${tool.accentColor}20`,
                      }}
                    >
                      {tool.badge}
                    </span>
                  </div>

                  {/* Tool Name */}
                  <h2
                    style={{
                      fontFamily: 'var(--font-heading)',
                      fontSize: 18,
                      fontWeight: 700,
                      color: '#0f172a',
                      marginBottom: 4,
                      letterSpacing: '-0.015em',
                    }}
                  >
                    {tool.title}
                  </h2>

                  <div
                    style={{
                      fontSize: 11.5,
                      fontWeight: 600,
                      color: '#6366f1',
                      marginBottom: 10,
                      letterSpacing: '-0.01em',
                    }}
                  >
                    {tool.tagline}
                  </div>

                  {/* Exact Approved Description */}
                  <p
                    style={{
                      fontSize: 13.5,
                      color: '#64748b',
                      lineHeight: 1.6,
                      margin: 0,
                    }}
                  >
                    {tool.description}
                  </p>
                </div>

                {/* Card Action */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    paddingTop: 16,
                    marginTop: 18,
                    borderTop: '1px solid rgba(99, 102, 241, 0.08)',
                  }}
                >
                  <div
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: 12.5,
                      fontWeight: 700,
                      color: tool.accentColor,
                    }}
                  >
                    <span>{tool.actionLabel}</span>
                    <ArrowRightIcon size={14} color={tool.accentColor} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          3. QUICK ACCESS & RECENT ACTIVITY (Tasteful, Subordinate)
      ───────────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.2fr 1fr',
          gap: 20,
        }}
        className="dashboard-secondary-grid"
      >
        {/* Recent Activity (Tasteful Empty State - No fake statistics or records) */}
        <div
          className="card"
          style={{
            padding: '22px 24px',
            background: '#ffffff',
            border: '1px solid rgba(99, 102, 241, 0.12)',
            borderRadius: 14,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <h3
              style={{
                fontFamily: 'var(--font-heading)',
                fontSize: 14.5,
                fontWeight: 700,
                color: '#0f172a',
                margin: 0,
              }}
            >
              Recent Activity
            </h3>
            <span
              onClick={() => navigate('/history')}
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: '#6366f1',
                cursor: 'pointer',
              }}
            >
              View All History →
            </span>
          </div>

          {/* Genuine Zero-State */}
          <div
            style={{
              padding: '24px 18px',
              background: '#f8f7ff',
              borderRadius: 10,
              border: '1px dashed rgba(99, 102, 241, 0.2)',
              textAlign: 'center',
            }}
          >
            <div style={{ marginBottom: 6, display: 'flex', justifyContent: 'center' }}>
              <LockIcon size={20} color="#94a3b8" />
            </div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#475569', margin: '0 0 3px' }}>
              No previous scan records yet
            </p>
            <p style={{ fontSize: 11.5, color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>
              Completed investigations across all four threat engines will be automatically archived here.
            </p>
          </div>
        </div>

        {/* Quick Access (Subordinate Secondary Navigation) */}
        <div
          className="card"
          style={{
            padding: '22px 24px',
            background: '#ffffff',
            border: '1px solid rgba(99, 102, 241, 0.12)',
            borderRadius: 14,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <h3
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 14.5,
              fontWeight: 700,
              color: '#0f172a',
              margin: '0 0 12px',
            }}
          >
            Quick Access
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {/* Quick Access Link 1: Scan History */}
            <div
              onClick={() => navigate('/history')}
              className="hover-lift"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '11px 14px',
                borderRadius: 10,
                background: '#f8f7ff',
                border: '1px solid rgba(99, 102, 241, 0.12)',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <LockIcon size={16} color="#6366f1" />
                <div>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: '#0f172a' }}>Scan History</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>Search past reports and forensic records</div>
                </div>
              </div>
              <ArrowRightIcon size={13} color="#94a3b8" />
            </div>

            {/* Quick Access Link 2: Security Awareness */}
            <div
              onClick={() => navigate('/security-awareness')}
              className="hover-lift"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '11px 14px',
                borderRadius: 10,
                background: '#f8f7ff',
                border: '1px solid rgba(99, 102, 241, 0.12)',
                cursor: 'pointer',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <ShieldIcon size={16} color="#6366f1" />
                <div>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: '#0f172a' }}>Security Awareness</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>Scam indicators and safety checklists</div>
                </div>
              </div>
              <ArrowRightIcon size={13} color="#94a3b8" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
