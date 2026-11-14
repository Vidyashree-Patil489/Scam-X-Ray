import { useNavigate } from 'react-router-dom';
import heroVisual from '../assets/hero-cyber-shield.png';
import {
  ShieldIcon,
  MessageSquareIcon,
  EyeScanIcon,
  BinaryFileIcon,
  ScaleCheckIcon,
  ArrowRightIcon,
  CheckCircleIcon
} from '../components/Icons';

export default function Home() {
  const navigate = useNavigate();

  const TOOLS = [
    {
      id: 'scam',
      title: 'Scam Detection',
      tagline: 'Text, URL & Screenshot Smishing Protection',
      description: 'Scan suspicious messages, recruitment offers, WhatsApp lures, and malicious URLs against 20+ scam heuristic indicators and trained ML classifiers.',
      icon: MessageSquareIcon,
      accent: '#6366f1',
      link: '/scam-detection',
    },
    {
      id: 'ai-image',
      title: 'AI Image Detection',
      tagline: 'Synthetic Generation & Diffusion Forensics',
      description: 'Analyze digital images for synthetic generation signatures, high-frequency residual noise anomalies, and diffusion artifacts to spot deepfakes and AI media.',
      icon: EyeScanIcon,
      accent: '#ec4899',
      link: '/ai-image-detection',
    },
    {
      id: 'stego',
      title: 'Steganography Scanner',
      tagline: 'Hidden Payloads & Structural File Forensics',
      description: 'Inspect images for concealed data, appended end-of-file (EOF) binary payloads, metadata discrepancies, and unusual least-significant-bit entropy variance.',
      icon: BinaryFileIcon,
      accent: '#06b6d4',
      link: '/steganography',
    },
    {
      id: 'fact-check',
      title: 'Fact Checker',
      tagline: 'Evidence Retrieval & Claim Verification',
      description: 'Verify news headlines, viral claims, and questionable media against verified encyclopedic sources with structured verdicts and clickable citations.',
      icon: ScaleCheckIcon,
      accent: '#10b981',
      link: '/fact-checker',
    },
  ];

  const STEPS = [
    {
      step: '01',
      title: 'Submit Content',
      desc: 'Paste suspicious text, submit a link, upload an image file, or enter a factual claim.',
    },
    {
      step: '02',
      title: 'Multi-Engine Analysis',
      desc: 'The dedicated engine analyzes heuristic rules, ML models, file structures, or factual evidence.',
    },
    {
      step: '03',
      title: 'Understand & Verify',
      desc: 'Review structured findings, risk scores, forensic metrics, and practical safety advice.',
    },
  ];

  const FLOATING_THREAT_LABELS = [
    { label: 'Threat Detected', top: '14%', right: '18%', delay: '0s', glow: 'rgba(239, 68, 68, 0.4)' },
    { label: 'Suspicious URL', top: '32%', right: '6%', delay: '1.2s', glow: 'rgba(245, 158, 11, 0.4)' },
    { label: 'AI Media Analysis', top: '56%', right: '8%', delay: '0.6s', glow: 'rgba(236, 72, 153, 0.4)' },
    { label: 'Hidden Payload Check', top: '78%', right: '22%', delay: '1.8s', glow: 'rgba(6, 182, 212, 0.4)' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg, #f8f7ff)', color: '#0f172a' }}>
      {/* ─────────────────────────────────────────────────────────────
          1. PUBLIC LANDING NAVBAR (Clean & Transparent)
      ───────────────────────────────────────────────────────────── */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 100,
          background: 'rgba(12, 7, 30, 0.85)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          borderBottom: '1px solid rgba(168, 85, 247, 0.18)',
          padding: '0 clamp(16px, 4vw, 48px)',
          height: 72,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: 12,
              background: 'linear-gradient(135deg, #a855f7, #ec4899)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ffffff',
              boxShadow: '0 0 20px rgba(168, 85, 247, 0.5)',
            }}
          >
            <ShieldIcon size={20} color="#ffffff" />
          </div>
          <div>
            <span style={{ fontWeight: 900, fontSize: 19, letterSpacing: '-0.02em', color: '#ffffff' }}>
              Scam<span style={{ color: '#c084fc' }}>XRay</span>
            </span>
          </div>
        </div>

        <nav
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 28,
          }}
          className="landing-nav-links"
        >
          <a
            href="#features"
            style={{ color: '#cbd5e1', fontSize: 14, fontWeight: 500, textDecoration: 'none', transition: 'color 0.2s' }}
            onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
            onMouseLeave={(e) => (e.target.style.color = '#cbd5e1')}
          >
            Features
          </a>
          <a
            href="#how-it-works"
            style={{ color: '#cbd5e1', fontSize: 14, fontWeight: 500, textDecoration: 'none', transition: 'color 0.2s' }}
            onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
            onMouseLeave={(e) => (e.target.style.color = '#cbd5e1')}
          >
            How It Works
          </a>
          <a
            href="#why-scamxray"
            style={{ color: '#cbd5e1', fontSize: 14, fontWeight: 500, textDecoration: 'none', transition: 'color 0.2s' }}
            onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
            onMouseLeave={(e) => (e.target.style.color = '#cbd5e1')}
          >
            Why ScamXRay
          </a>
        </nav>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={() => navigate('/dashboard')}
            className="btn-primary"
            style={{
              background: 'linear-gradient(135deg, #9333ea, #db2777)',
              padding: '10px 22px',
              fontSize: 13,
              borderRadius: 50,
              boxShadow: '0 4px 20px rgba(168, 85, 247, 0.45)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span>Open Dashboard</span>
            <ArrowRightIcon size={14} color="#ffffff" />
          </button>
        </div>
      </header>

      {/* ─────────────────────────────────────────────────────────────
          2. HERO SECTION (Cybersecurity Visual Reference Inspired)
      ───────────────────────────────────────────────────────────── */}
      <section
        style={{
          position: 'relative',
          background: 'radial-gradient(ellipse 90% 70% at 65% 45%, #2a0845 0%, #150628 45%, #0c0418 100%)',
          color: '#ffffff',
          padding: 'clamp(50px, 8vw, 90px) clamp(20px, 5vw, 64px) clamp(60px, 9vw, 110px)',
          overflow: 'hidden',
          borderBottom: '1px solid rgba(168, 85, 247, 0.2)',
        }}
      >
        {/* Subtle grid backdrop overlay */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage: 'radial-gradient(rgba(168, 85, 247, 0.15) 1px, transparent 1px)',
            backgroundSize: '36px 36px',
            opacity: 0.6,
            pointerEvents: 'none',
          }}
        />

        {/* Ambient magenta/purple light beams */}
        <div
          style={{
            position: 'absolute',
            top: '-15%',
            left: '-10%',
            width: '600px',
            height: '600px',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(147, 51, 234, 0.3) 0%, transparent 70%)',
            filter: 'blur(80px)',
            pointerEvents: 'none',
          }}
        />
        <div
          style={{
            position: 'absolute',
            top: '20%',
            right: '-10%',
            width: '650px',
            height: '650px',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(219, 39, 119, 0.25) 0%, transparent 70%)',
            filter: 'blur(90px)',
            pointerEvents: 'none',
          }}
        />

        <div
          style={{
            maxWidth: 1300,
            margin: '0 auto',
            display: 'grid',
            gridTemplateColumns: '1.05fr 1fr',
            alignItems: 'center',
            gap: 'clamp(32px, 6vw, 64px)',
            position: 'relative',
            zIndex: 10,
          }}
          className="hero-grid-layout"
        >
          {/* Left Column: Headline & Value Proposition */}
          <div className="fade-up">
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                background: 'rgba(168, 85, 247, 0.15)',
                border: '1px solid rgba(168, 85, 247, 0.4)',
                borderRadius: 40,
                padding: '6px 16px',
                marginBottom: 24,
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
              }}
            >
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: '#c084fc',
                  boxShadow: '0 0 10px #c084fc',
                }}
              />
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f3e8ff', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                Next-Gen Digital Threat Intelligence
              </span>
            </div>

            <h1
              style={{
                fontSize: 'clamp(34px, 4.8vw, 60px)',
                fontWeight: 900,
                lineHeight: 1.1,
                letterSpacing: '-0.03em',
                marginBottom: 22,
                color: '#ffffff',
              }}
            >
              Decode Deception.<br />
              <span
                style={{
                  background: 'linear-gradient(90deg, #f0abfc 0%, #c084fc 40%, #f472b6 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}
              >
                Stay One Step Ahead.
              </span>
            </h1>

            <p
              style={{
                fontSize: 'clamp(15px, 1.3vw, 17px)',
                lineHeight: 1.8,
                color: '#cbd5e1',
                marginBottom: 36,
                maxWidth: 540,
              }}
            >
              From suspicious messages and AI-generated images to hidden data and misleading claims, ScamXRay brings powerful digital threat analysis tools together in one place.
            </p>

            {/* CTA Buttons */}
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
              <button
                onClick={() => navigate('/dashboard')}
                className="btn-primary"
                style={{
                  background: 'linear-gradient(135deg, #a855f7 0%, #ec4899 100%)',
                  fontSize: 15,
                  padding: '14px 30px',
                  borderRadius: 50,
                  boxShadow: '0 8px 32px rgba(168, 85, 247, 0.45)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <span>Explore ScamXRay</span>
                <ArrowRightIcon size={16} color="#ffffff" />
              </button>

              <a
                href="#features"
                style={{
                  background: 'rgba(255, 255, 255, 0.08)',
                  color: '#ffffff',
                  border: '1px solid rgba(255, 255, 255, 0.25)',
                  borderRadius: 50,
                  padding: '13px 26px',
                  fontSize: 15,
                  fontWeight: 600,
                  textDecoration: 'none',
                  backdropFilter: 'blur(10px)',
                  WebkitBackdropFilter: 'blur(10px)',
                  transition: 'all 0.25s',
                  display: 'inline-block',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.16)';
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.45)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.25)';
                }}
              >
                Discover Features
              </a>
            </div>

            {/* Quick trust metrics */}
            <div
              style={{
                display: 'flex',
                gap: 28,
                marginTop: 44,
                paddingTop: 28,
                borderTop: '1px solid rgba(255, 255, 255, 0.12)',
              }}
            >
              <div>
                <div style={{ fontSize: 24, fontWeight: 900, color: '#f0abfc' }}>4</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                  Forensic Modules
                </div>
              </div>
              <div style={{ width: 1, background: 'rgba(255, 255, 255, 0.12)' }} />
              <div>
                <div style={{ fontSize: 24, fontWeight: 900, color: '#c084fc' }}>100%</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                  Privacy Focused
                </div>
              </div>
              <div style={{ width: 1, background: 'rgba(255, 255, 255, 0.12)' }} />
              <div>
                <div style={{ fontSize: 24, fontWeight: 900, color: '#f472b6' }}>Instant</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                  Local Heuristics
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Hero Visual + Floating Threat Labels */}
          <div
            style={{
              position: 'relative',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
            className="hero-visual-wrapper"
          >
            {/* The 3D Cybersecurity Device Image */}
            <div
              style={{
                position: 'relative',
                width: '100%',
                maxWidth: 560,
                borderRadius: 24,
                overflow: 'hidden',
                boxShadow: '0 20px 60px rgba(0, 0, 0, 0.6), 0 0 50px rgba(168, 85, 247, 0.3)',
                border: '1px solid rgba(192, 132, 252, 0.3)',
              }}
              className="floating"
            >
              <img
                src={heroVisual}
                alt="ScamXRay 3D Cybersecurity Threat Core"
                style={{
                  width: '100%',
                  height: 'auto',
                  display: 'block',
                  transform: 'scale(1.02)',
                  transition: 'transform 0.5s ease',
                }}
              />
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  background: 'linear-gradient(180deg, transparent 65%, rgba(12, 4, 24, 0.8) 100%)',
                  pointerEvents: 'none',
                }}
              />
            </div>

            {/* Floating threat-intelligence badges inspired by reference image */}
            {FLOATING_THREAT_LABELS.map((item, index) => (
              <div
                key={index}
                className="floating-threat-pill"
                style={{
                  position: 'absolute',
                  top: item.top,
                  right: item.right,
                  background: 'rgba(15, 7, 32, 0.85)',
                  backdropFilter: 'blur(14px)',
                  WebkitBackdropFilter: 'blur(14px)',
                  border: '1px solid rgba(192, 132, 252, 0.4)',
                  boxShadow: `0 8px 24px ${item.glow}`,
                  borderRadius: 30,
                  padding: '7px 16px',
                  fontSize: 11,
                  fontWeight: 700,
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  zIndex: 20,
                  pointerEvents: 'none',
                  animationDelay: item.delay,
                }}
              >
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    background: '#f472b6',
                    boxShadow: '0 0 8px #f472b6',
                  }}
                />
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          3. SECTION 1: WHAT SCAMXRAY OFFERS (4 Major Engines)
      ───────────────────────────────────────────────────────────── */}
      <section
        id="features"
        style={{
          padding: '90px clamp(20px, 5vw, 64px)',
          maxWidth: 1280,
          margin: '0 auto',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 54 }}>
          <div
            style={{
              display: 'inline-block',
              background: 'rgba(99, 102, 241, 0.1)',
              color: '#6366f1',
              borderRadius: 30,
              padding: '6px 16px',
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              marginBottom: 14,
            }}
          >
            Unified Architecture
          </div>
          <h2
            style={{
              fontSize: 'clamp(28px, 3.5vw, 42px)',
              fontWeight: 900,
              color: '#0f172a',
              letterSpacing: '-0.025em',
              marginBottom: 14,
            }}
          >
            One Platform. Four Layers of Digital Protection.
          </h2>
          <p style={{ fontSize: 16, color: '#64748b', maxWidth: 620, margin: '0 auto', lineHeight: 1.7 }}>
            A centralized digital safety platform designed to identify deceptive interactions across communications, media, and factual content.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))',
            gap: 24,
          }}
        >
          {TOOLS.map((tool) => {
            const Icon = tool.icon;
            return (
              <div
                key={tool.id}
                onClick={() => navigate(tool.link)}
                className="card hover-lift"
                style={{
                  padding: 30,
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  border: '1px solid rgba(99, 102, 241, 0.12)',
                }}
              >
                <div>
                  <div
                    style={{
                      width: 52,
                      height: 52,
                      borderRadius: 14,
                      background: `linear-gradient(135deg, ${tool.accent}18, ${tool.accent}32)`,
                      border: `1.5px solid ${tool.accent}35`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: tool.accent,
                      marginBottom: 20,
                    }}
                  >
                    <Icon size={26} color={tool.accent} />
                  </div>

                  <h3 style={{ fontSize: 19, fontWeight: 800, color: '#0f172a', marginBottom: 6 }}>
                    {tool.title}
                  </h3>

                  <div style={{ fontSize: 11, fontWeight: 700, color: '#6366f1', marginBottom: 12 }}>
                    {tool.tagline}
                  </div>

                  <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, marginBottom: 20 }}>
                    {tool.description}
                  </p>
                </div>

                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 13,
                    fontWeight: 700,
                    color: tool.accent,
                    paddingTop: 16,
                    borderTop: '1px solid rgba(99, 102, 241, 0.08)',
                  }}
                >
                  <span>Open Tool</span>
                  <ArrowRightIcon size={14} color={tool.accent} />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          4. SECTION 2: HOW IT WORKS (3 Simple Steps)
      ───────────────────────────────────────────────────────────── */}
      <section
        id="how-it-works"
        style={{
          background: '#ffffff',
          borderTop: '1px solid rgba(99, 102, 241, 0.1)',
          borderBottom: '1px solid rgba(99, 102, 241, 0.1)',
          padding: '80px clamp(20px, 5vw, 64px)',
        }}
      >
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 50 }}>
            <div
              style={{
                display: 'inline-block',
                background: 'rgba(99, 102, 241, 0.08)',
                color: '#6366f1',
                borderRadius: 30,
                padding: '5px 14px',
                fontSize: 12,
                fontWeight: 700,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                marginBottom: 12,
              }}
            >
              Inspection Workflow
            </div>
            <h2 style={{ fontSize: 'clamp(26px, 3.2vw, 38px)', fontWeight: 900, color: '#0f172a' }}>
              How ScamXRay Works
            </h2>
            <p style={{ fontSize: 15, color: '#64748b', marginTop: 8 }}>
              Three straightforward steps from suspicious input to transparent forensic findings.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))',
              gap: 24,
            }}
          >
            {STEPS.map((s, index) => (
              <div
                key={index}
                style={{
                  background: 'var(--bg, #f8f7ff)',
                  border: '1px solid rgba(99, 102, 241, 0.12)',
                  borderRadius: 18,
                  padding: 30,
                  position: 'relative',
                }}
              >
                <div
                  style={{
                    fontSize: 13,
                    fontWeight: 800,
                    fontFamily: 'Space Mono, monospace',
                    color: '#6366f1',
                    background: 'rgba(99, 102, 241, 0.12)',
                    display: 'inline-block',
                    padding: '4px 10px',
                    borderRadius: 8,
                    marginBottom: 16,
                  }}
                >
                  STEP {s.step}
                </div>

                <h3 style={{ fontSize: 18, fontWeight: 800, color: '#0f172a', marginBottom: 10 }}>
                  {s.title}
                </h3>

                <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, margin: 0 }}>
                  {s.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          5. SECTION 3: WHY SCAMXRAY (Realistic Value Proposition)
      ───────────────────────────────────────────────────────────── */}
      <section
        id="why-scamxray"
        style={{
          padding: '90px clamp(20px, 5vw, 64px)',
          maxWidth: 1100,
          margin: '0 auto',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <h2 style={{ fontSize: 'clamp(26px, 3vw, 36px)', fontWeight: 900, color: '#0f172a', marginBottom: 12 }}>
            Why Consolidate Threat Verification?
          </h2>
          <p style={{ fontSize: 15, color: '#64748b', maxWidth: 640, margin: '0 auto', lineHeight: 1.7 }}>
            Modern digital attacks rarely rely on a single vector. Fraudsters combine smishing, deceptive links, synthetic media, and fake news to build false credibility.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 320px), 1fr))',
            gap: 20,
          }}
        >
          <div className="card" style={{ padding: 26, border: '1px solid rgba(99, 102, 241, 0.12)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <CheckCircleIcon size={20} color="#6366f1" />
              <h4 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Cross-Domain Analysis</h4>
            </div>
            <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, margin: 0 }}>
              Verify an internship message, scan its included link, inspect an attached poster screenshot, and cross-reference recruiter claims without juggling separate disjointed tools.
            </p>
          </div>

          <div className="card" style={{ padding: 26, border: '1px solid rgba(99, 102, 241, 0.12)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <CheckCircleIcon size={20} color="#6366f1" />
              <h4 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Transparent Explanations</h4>
            </div>
            <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, margin: 0 }}>
              Rather than returning an opaque black-box score, ScamXRay outlines exact matched heuristic rules, spectral noise distributions, or verified source citations.
            </p>
          </div>

          <div className="card" style={{ padding: 26, border: '1px solid rgba(99, 102, 241, 0.12)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <CheckCircleIcon size={20} color="#6366f1" />
              <h4 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Privacy & Data Integrity</h4>
            </div>
            <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7, margin: 0 }}>
              Scans operate without mandatory user tracking or credentials. You maintain control over your inspection history and can clear all records at any time.
            </p>
          </div>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          6. SECTION 4: FINAL CALL TO ACTION
      ───────────────────────────────────────────────────────────── */}
      <section
        style={{
          background: 'linear-gradient(135deg, #180933 0%, #3b0764 50%, #180933 100%)',
          color: '#ffffff',
          padding: '80px clamp(20px, 5vw, 64px)',
          textAlign: 'center',
          position: 'relative',
          overflow: 'hidden',
          borderTop: '1px solid rgba(168, 85, 247, 0.3)',
        }}
      >
        <div style={{ maxWidth: 720, margin: '0 auto', position: 'relative', zIndex: 10 }}>
          <h2
            style={{
              fontSize: 'clamp(28px, 4vw, 42px)',
              fontWeight: 900,
              letterSpacing: '-0.025em',
              marginBottom: 16,
              color: '#ffffff',
            }}
          >
            Think Before You Trust. Verify with ScamXRay.
          </h2>

          <p style={{ fontSize: 16, color: '#e2e8f0', marginBottom: 32, lineHeight: 1.7 }}>
            Access all four digital threat intelligence engines instantly in your browser.
          </p>

          <button
            onClick={() => navigate('/dashboard')}
            className="btn-primary"
            style={{
              background: 'linear-gradient(135deg, #a855f7 0%, #ec4899 100%)',
              fontSize: 16,
              padding: '16px 36px',
              borderRadius: 50,
              boxShadow: '0 8px 30px rgba(236, 72, 153, 0.4)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 10,
            }}
          >
            <span>Open ScamXRay Dashboard</span>
            <ArrowRightIcon size={16} color="#ffffff" />
          </button>
        </div>
      </section>

      {/* ─────────────────────────────────────────────────────────────
          7. SECTION 5: FOOTER
      ───────────────────────────────────────────────────────────── */}
      <footer
        style={{
          background: '#090314',
          color: '#94a3b8',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          padding: '60px clamp(20px, 5vw, 64px) 40px',
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: '0 auto',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 220px), 1fr))',
            gap: 40,
            marginBottom: 48,
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 10,
                  background: 'linear-gradient(135deg, #a855f7, #ec4899)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#ffffff',
                }}
              >
                <ShieldIcon size={18} color="#ffffff" />
              </div>
              <span style={{ fontWeight: 900, fontSize: 18, color: '#ffffff' }}>
                Scam<span style={{ color: '#c084fc' }}>XRay</span>
              </span>
            </div>
            <p style={{ fontSize: 13, lineHeight: 1.7, color: '#94a3b8' }}>
              Intelligent digital safety platform unifying scam detection, synthetic media analysis, forensic steganography, and factual claim verification.
            </p>
          </div>

          <div>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#ffffff', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 16 }}>
              Threat Engines
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
              <span onClick={() => navigate('/scam-detection')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Scam Detection</span>
              <span onClick={() => navigate('/ai-image-detection')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>AI Image Detection</span>
              <span onClick={() => navigate('/steganography')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Steganography Scanner</span>
              <span onClick={() => navigate('/fact-checker')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Fact Checker</span>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#ffffff', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 16 }}>
              Platform
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 13 }}>
              <span onClick={() => navigate('/dashboard')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Dashboard</span>
              <span onClick={() => navigate('/history')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Scan History</span>
              <span onClick={() => navigate('/security-awareness')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>Security Awareness</span>
              <span onClick={() => navigate('/about')} style={{ cursor: 'pointer', color: '#cbd5e1' }}>About Platform</span>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: '#ffffff', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 16 }}>
              Legal & Verification
            </h4>
            <p style={{ fontSize: 12, lineHeight: 1.7, color: '#64748b' }}>
              ScamXRay provides heuristic risk estimates and evidence cross-references. Results are advisory and should be independently verified prior to financial or career commitments.
            </p>
          </div>
        </div>

        <div
          style={{
            maxWidth: 1200,
            margin: '0 auto',
            paddingTop: 24,
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 12,
            fontSize: 12,
            color: '#64748b',
          }}
        >
          <span>© {new Date().getFullYear()} ScamXRay Threat Intelligence Platform. All rights reserved.</span>
          <span>Designed for Digital Safety and Misinformation Defense.</span>
        </div>
      </footer>
    </div>
  );
}
