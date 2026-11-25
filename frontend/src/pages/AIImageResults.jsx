import { useLocation, useNavigate, Link, Navigate } from 'react-router-dom';
import { LimitationsCard } from './AIImageDetection';

export default function AIImageResults() {
  const location = useLocation();
  const navigate = useNavigate();

  const result = location.state?.result;
  const image = location.state?.image;
  const imageUrl = location.state?.imageUrl;
  const filename = location.state?.filename || image?.name || 'Uploaded image';

  // If opened without state, redirect cleanly to detection upload page
  if (!result) {
    return <Navigate to="/ai-image-detection" replace />;
  }

  // Extract model probabilities
  const aiPred = result.all_predictions?.find((p) => p.label === 'AI-generated');
  const humanPred = result.all_predictions?.find((p) => p.label === 'human');
  const aiScore = aiPred ? aiPred.confidence : result.label === 'AI-generated' ? result.confidence : 0;
  const humanScore = humanPred ? humanPred.confidence : result.label === 'human' ? result.confidence : 0;

  const getResultBadgeStyle = (verdict) => {
    if (verdict === 'Likely AI-generated') {
      return {
        background: 'rgba(239, 68, 68, 0.08)',
        border: '1px solid rgba(239, 68, 68, 0.25)',
        color: '#dc2626',
      };
    } else if (verdict === 'Likely human-created') {
      return {
        background: 'rgba(16, 185, 129, 0.08)',
        border: '1px solid rgba(16, 185, 129, 0.25)',
        color: '#059669',
      };
    }
    return {
      background: 'rgba(245, 158, 11, 0.08)',
      border: '1px solid rgba(245, 158, 11, 0.25)',
      color: '#d97706',
    };
  };

  const getVerdictMeaning = () => {
    if (result.result === 'Likely AI-generated') {
      return `The model estimates a ${aiScore}% probability that this image is AI-generated. It does not show which parts of the image led to this result.`;
    }
    if (result.result === 'Likely human-created') {
      return `The model estimates a ${humanScore}% probability that this image is human-created. This does not prove the image is authentic or unedited.`;
    }
    return "The model's confidence was below 65%, so the result is not reliable either way. Treat it as unverified and check the image manually.";
  };

  return (
    <div className="fade-up" style={{ maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─────────────────────────────────────────────────────────────
          SECTION A: HEADER
      ───────────────────────────────────────────────────────────── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 8 }}>
          <Link
            to="/ai-image-detection"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 13,
              color: '#6366f1',
              textDecoration: 'none',
              fontWeight: 600,
            }}
          >
            ← Back to Image Detection
          </Link>
          <button
            onClick={() => navigate('/ai-image-detection')}
            className="btn-primary"
            style={{
              padding: '8px 18px',
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            Analyze another image
          </button>
        </div>

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
            marginBottom: 10,
          }}
        >
          Synthetic Media Inspection
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
          AI Image Detection Report
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
          Analysis report for: <strong>{filename}</strong>
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION B: VERDICT CARD
      ───────────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 16px',
          }}
        >
          Detection Verdict
        </h2>

        {imageUrl && (
          <div style={{ marginBottom: 20 }}>
            <div
              style={{
                display: 'inline-block',
                borderRadius: 10,
                overflow: 'hidden',
                border: '1px solid var(--border)',
                background: '#f8fafc',
                padding: 6,
              }}
            >
              <img
                src={imageUrl}
                alt="Analyzed preview"
                style={{
                  maxHeight: '240px',
                  maxWidth: '100%',
                  objectFit: 'contain',
                  display: 'block',
                  borderRadius: 6,
                }}
              />
            </div>
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 14, marginBottom: 18 }}>
          <span
            style={{
              display: 'inline-block',
              padding: '6px 16px',
              borderRadius: 20,
              fontSize: 15,
              fontWeight: 700,
              ...getResultBadgeStyle(result.result),
            }}
          >
            {result.result}
          </span>
          <span style={{ fontSize: 14.5, color: '#64748b' }}>
            Confidence: <strong style={{ color: '#0f172a' }}>{result.confidence}%</strong>
          </span>
        </div>

        {/* Class Probabilities Bars */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12, paddingTop: 16, borderTop: '1px solid rgba(99, 102, 241, 0.12)' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13.5, marginBottom: 6 }}>
              <span style={{ fontWeight: 600, color: '#334155' }}>AI-generated</span>
              <span style={{ fontWeight: 700, color: '#0f172a' }}>{aiScore}%</span>
            </div>
            <div style={{ height: 8, borderRadius: 4, background: 'rgba(99, 102, 241, 0.15)', overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(100, Math.max(0, aiScore))}%`, height: '100%', background: '#6366f1', borderRadius: 4, transition: 'width 0.4s ease' }} />
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13.5, marginBottom: 6 }}>
              <span style={{ fontWeight: 600, color: '#334155' }}>Human-created</span>
              <span style={{ fontWeight: 700, color: '#0f172a' }}>{humanScore}%</span>
            </div>
            <div style={{ height: 8, borderRadius: 4, background: 'rgba(99, 102, 241, 0.15)', overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(100, Math.max(0, humanScore))}%`, height: '100%', background: '#6366f1', borderRadius: 4, transition: 'width 0.4s ease' }} />
            </div>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION C: WHAT THIS RESULT MEANS
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
          What This Result Means
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          {getVerdictMeaning()}
        </p>
        <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: 0 }}>
          Classification uses a 65% confidence rule: scores of 65% or higher assign a directional verdict, whereas scores below 65% are classified as Inconclusive. The model estimated an AI-generated probability of {aiScore}% and a human-created probability of {humanScore}%.
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION D: WHAT TO LOOK FOR IN IMAGES
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
          What to Look for in Images
        </h2>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: 14.5, fontWeight: 700, color: '#0f172a', margin: '0 0 6px' }}>
              Look closely
            </h3>
            <p style={{ fontSize: 14, color: '#475569', lineHeight: 1.6, margin: 0 }}>
              hands, fingers and teeth that look wrong; garbled, misspelled or meaningless text on signs, posters and clothing; inconsistent lighting, shadows or reflections; warped lines or objects in the background; repeated textures or patterns; mismatched jewellery, glasses or ears; skin or surfaces that look unnaturally smooth.
            </p>
          </div>

          <div>
            <h3 style={{ fontFamily: 'var(--font-heading)', fontSize: 14.5, fontWeight: 700, color: '#0f172a', margin: '0 0 6px' }}>
              Check the source
            </h3>
            <p style={{ fontSize: 14, color: '#475569', lineHeight: 1.6, margin: 0 }}>
              run a reverse image search (for example Google Lens or TinEye) to find where the image first appeared; check who posted it and whether it appears on reliable sources; look for Content Credentials or a label saying the image is AI-generated, remembering that most images carry none and a missing label proves nothing; be extra careful when an image is used to make you pay, hurry or share personal details.
            </p>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION E: HOW THIS WAS ANALYSED
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
          How This Was Analysed
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 10px' }}>
          This analysis was performed using{' '}
          <a
            href="https://huggingface.co/aaronkantrowitz/ai-human-generated-image-detection"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#6366f1', textDecoration: 'underline', fontWeight: 600 }}
          >
            aaronkantrowitz/ai-human-generated-image-detection
          </a>
          . This is a third-party model and no accuracy figures are claimed.
        </p>
        <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: 0 }}>
          Your image was sent to the ScamXRay server, analysed in memory and not stored.
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          SECTION F: LIMITATIONS & GUIDANCE (AFTER RESULT)
      ───────────────────────────────────────────────────────────── */}
      <LimitationsCard />
    </div>
  );
}
