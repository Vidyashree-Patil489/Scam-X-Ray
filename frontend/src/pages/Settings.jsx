import { Link } from 'react-router-dom';

export default function Settings() {
  return (
    <div className="fade-up" style={{ maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div>
        <div
          style={{
            display: 'inline-block',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.12), rgba(118, 75, 162, 0.12))',
            color: '#6366f1',
            fontSize: 11,
            fontWeight: 800,
            padding: '5px 14px',
            borderRadius: 20,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: 12,
          }}
        >
          Platform Settings & Privacy
        </div>
        <h1
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'clamp(24px, 3vw, 32px)',
            fontWeight: 800,
            color: '#0f172a',
            margin: '0 0 8px',
            letterSpacing: '-0.02em',
          }}
        >
          Settings & Architecture
        </h1>
        <p
          style={{
            fontFamily: 'var(--font-body)',
            fontSize: 15,
            color: '#64748b',
            margin: 0,
            lineHeight: 1.6,
          }}
        >
          Operational status, analysis engine mechanics, data privacy architecture, and advisory boundaries.
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION 1: ENGINE STATUS
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 14px',
          }}
        >
          1. Engine Status
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 7,
              background: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: 20,
              padding: '5px 12px',
              fontSize: 12,
              fontWeight: 600,
              color: '#059669',
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: '#10b981',
                boxShadow: '0 0 6px rgba(16, 185, 129, 0.6)',
              }}
            />
            Engine Ready
          </div>
          <span style={{ fontSize: 13, color: '#64748b' }}>
            Operational (local heuristics, ML classification, and URL verification)
          </span>
        </div>
        <p style={{ fontSize: 14, color: '#475569', lineHeight: 1.6, margin: 0 }}>
          This status reflects the operational readiness of the ScamXRay analysis pipeline, matching the indicator displayed in the navigation bar.
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION 2: WHAT SCAMXRAY CHECKS
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          2. What ScamXRay Checks
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          ScamXRay investigates digital content through dedicated detection pipelines:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>Text and messages:</strong> Analyzes content using heuristic rules, a trained machine learning classifier, and an AI assessment, combined into one calibrated risk score.
          </li>
          <li>
            <strong>Links:</strong> Performs URL structure checks, DNS resolution, TLS certificate verification, domain age queries, and HTTP reachability checks, alongside comparisons against the OpenPhish community phishing feed. Returns structured verdicts: <em>Malicious</em>, <em>Suspicious</em>, <em>No threat found</em>, or <em>Unknown</em>.
          </li>
          <li>
            <strong>Screenshots:</strong> Text is read directly from the image in your browser using optical character recognition (OCR), then analyzed through the message inspection pipeline.
          </li>
        </ul>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION 3: PRIVACY AND DATA
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          3. Privacy and Data Handling
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          How submitted content and queries are processed across our systems:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>What is sent to our backend:</strong> When submitting text or links, only the raw text or URL string is sent to our server via JSON. For screenshot scans, OCR text extraction executes locally in your browser—the image file itself is never transmitted to our backend.
          </li>
          <li>
            <strong>External AI service:</strong> Message text (up to the first 3,000 characters) is sent to Groq&apos;s API (<code style={{ fontSize: 13, background: '#f1f5f9', padding: '2px 6px', borderRadius: 4 }}>openai/gpt-oss-20b</code>) to generate plain-language risk explanations and actionable tips. If unavailable, local fallback explanations are used.
          </li>
          <li>
            <strong>URL scan network requests:</strong> To inspect links, our backend contacts public DNS resolvers to look up domain IP addresses, connects to the target website to verify its TLS certificate and HTTP reachability, queries the public RDAP service (<code style={{ fontSize: 13, background: '#f1f5f9', padding: '2px 6px', borderRadius: 4 }}>rdap.org</code>) for domain registration age, and periodically downloads the public OpenPhish feed (<code style={{ fontSize: 13, background: '#f1f5f9', padding: '2px 6px', borderRadius: 4 }}>openphish.com</code>). All requests enforce strict SSRF guards blocking connections to private or internal network addresses.
          </li>
          <li>
            <strong>No accounts or sign-in:</strong> No user registration, login credentials, authentication tokens, or personal identifiers are required to perform scans.
          </li>
          <li>
            <strong>Scan results are not stored:</strong> Scan submissions, extracted text, and inspection reports are not stored or persisted in any database or file on our server. All processing is held in memory and returned immediately.
          </li>
        </ul>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION 4: LIMITS OF AUTOMATED ANALYSIS
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          4. Limits of Automated Analysis
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          Important boundaries to understand when interpreting scan outcomes:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>Advisory nature:</strong> Results, risk scores, and threat indicators are automated assessments and should be treated as guidance rather than definitive legal or security conclusions.
          </li>
          <li>
            <strong>No safety guarantee:</strong> A verdict of &quot;No threat found&quot; is not a guarantee that a link or communication is safe. Attackers continuously create new domains and deceptive variations.
          </li>
          <li>
            <strong>Verify with official sources:</strong> Always verify job offers, payment requests, or account warnings independently through official websites, phone directories, or authorized apps.
          </li>
        </ul>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION 5: ABOUT
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          5. About ScamXRay
        </h2>
        <p style={{ fontSize: 14.5, color: '#334155', lineHeight: 1.7, margin: '0 0 16px' }}>
          <strong>ScamXRay</strong> is an intelligent digital safety platform unifying multi-vector scam detection and synthetic media analysis to protect users against modern online deception.
        </p>
        <div>
          <Link
            to="/security-awareness"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              background: '#f8f7ff',
              border: '1px solid rgba(99, 102, 241, 0.2)',
              color: '#6366f1',
              padding: '10px 18px',
              borderRadius: 10,
              fontSize: 13,
              fontWeight: 700,
              textDecoration: 'none',
            }}
            className="hover-lift"
          >
            <span>Explore the Security Awareness & Prevention Guide</span>
            <span>→</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
