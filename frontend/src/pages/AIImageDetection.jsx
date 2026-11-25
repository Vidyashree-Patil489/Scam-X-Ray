import { useState } from 'react';

export default function AIImageDetection() {
  const [image, setImage] = useState(null);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleImageChange = (e) => {
    const file = e.target.files[0];

    if (!file) return;

    setImage(file);
    setPreview(URL.createObjectURL(file));
    setResult(null);
    setError('');
  };

  const handleAnalyze = async () => {
    if (!image) {
      setError('Please select an image first.');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('image', image);

      const response = await fetch(
        'http://127.0.0.1:5000/analyze-image',
        {
          method: 'POST',
          body: formData,
        }
      );

      let data;
      try {
        data = await response.json();
      } catch {
        data = null;
      }

      if (!response.ok || !data?.success) {
        if (response.status === 400) {
          throw new Error(data?.error || 'Invalid or empty image file. Please provide a valid JPEG, PNG, or WebP image.');
        } else if (response.status === 413) {
          throw new Error(data?.error || 'The uploaded image exceeds the maximum allowed size of 5 MB.');
        } else if (response.status === 415) {
          throw new Error(data?.error || 'Unsupported image format. Only JPEG, PNG, and WebP are allowed.');
        } else if (response.status === 503) {
          throw new Error(data?.error || 'Image detection is temporarily unavailable.');
        } else {
          throw new Error(data?.error || 'Image analysis failed. Please try again.');
        }
      }

      setResult(data);
    } catch (err) {
      if (err.name === 'TypeError' || err.message.includes('fetch') || err.message.includes('NetworkError') || err.message.includes('Failed to fetch')) {
        setError('Unable to connect to the backend server. Please verify the service is running.');
      } else {
        setError(err.message || 'Unable to connect to the backend.');
      }
    } finally {
      setLoading(false);
    }
  };

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

  return (
    <div className="fade-up" style={{ maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Page Header */}
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
          AI Image Detection
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
          Upload an image to check whether it is likely AI-generated or human-created.
        </p>
      </div>

      {/* Upload Box Card */}
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
          Select Image
        </h2>

        <div style={{ marginBottom: 16 }}>
          <input
            type="file"
            accept="image/jpeg,image/png,image/webp"
            onChange={handleImageChange}
            style={{
              display: 'block',
              fontSize: 14,
              color: '#475569',
              fontFamily: 'var(--font-body)',
            }}
          />
          <span style={{ fontSize: 12, color: '#94a3b8', marginTop: 6, display: 'block' }}>
            Supported formats: JPEG, PNG, WebP (max 5 MB)
          </span>
        </div>

        {preview && (
          <div style={{ margin: '16px 0' }}>
            <h3
              style={{
                fontFamily: 'var(--font-heading)',
                fontSize: 14,
                fontWeight: 600,
                color: '#334155',
                marginBottom: 8,
              }}
            >
              Image Preview
            </h3>
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
                src={preview}
                alt="Uploaded preview"
                style={{
                  maxWidth: '300px',
                  maxHeight: '300px',
                  objectFit: 'contain',
                  display: 'block',
                  borderRadius: 6,
                }}
              />
            </div>
          </div>
        )}

        <div style={{ marginTop: 18 }}>
          <button
            onClick={handleAnalyze}
            disabled={!image || loading}
            className="btn-primary"
            style={{
              padding: '10px 24px',
              fontSize: 14,
              fontWeight: 700,
              cursor: (!image || loading) ? 'not-allowed' : 'pointer',
              opacity: (!image || loading) ? 0.6 : 1,
            }}
          >
            {loading ? 'Analyzing Image...' : 'Analyze Image'}
          </button>
        </div>

        {/* Loading State Notice */}
        {loading && (
          <div
            style={{
              marginTop: 16,
              padding: '12px 16px',
              borderRadius: 8,
              background: 'rgba(99, 102, 241, 0.08)',
              border: '1px solid rgba(99, 102, 241, 0.2)',
              color: '#4f46e5',
              fontSize: 13.5,
              lineHeight: 1.5,
            }}
          >
            <strong>Analyzing image:</strong> The first scan downloads the model and can take a minute.
          </div>
        )}

        {/* Error State */}
        {error && (
          <div
            style={{
              marginTop: 16,
              padding: '12px 16px',
              borderRadius: 8,
              background: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              color: '#dc2626',
              fontSize: 14,
              lineHeight: 1.5,
            }}
          >
            <strong>Error:</strong> {error}
          </div>
        )}
      </div>

      {/* Detection Result Card */}
      {result && (
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
            Detection Result
          </h2>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
            <span
              style={{
                display: 'inline-block',
                padding: '6px 14px',
                borderRadius: 20,
                fontSize: 15,
                fontWeight: 700,
                ...getResultBadgeStyle(result.result),
              }}
            >
              {result.result}
            </span>
            <span style={{ fontSize: 14, color: '#64748b' }}>
              Confidence: <strong>{result.confidence}%</strong>
            </span>
          </div>

          <p style={{ fontSize: 13.5, color: '#475569', margin: '0 0 6px' }}>
            Model Label: <code style={{ fontSize: 13, background: '#f1f5f9', padding: '2px 6px', borderRadius: 4 }}>{result.label}</code>
          </p>

          {result.all_predictions && result.all_predictions.length > 0 && (
            <div style={{ marginTop: 12, fontSize: 13, color: '#64748b' }}>
              <span>Class probabilities: </span>
              {result.all_predictions.map((p, idx) => (
                <span key={p.label}>
                  {p.label}: {p.confidence}%{idx < result.all_predictions.length - 1 ? ' | ' : ''}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Limitations Note Card */}
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
          Limitations & Guidance
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 10px' }}>
          Automated image analysis can be wrong. Compressed, edited or screenshotted images are especially hard to judge. Do not treat this as proof.
        </p>
        <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: 0 }}>
          <strong>What &quot;Inconclusive&quot; means:</strong> The model did not attain the minimum confidence threshold (65%) or the visual signals were ambiguous between human and synthetic origin. Inconclusive outcomes require manual inspection and should not be relied upon as verification of authenticity or synthetic generation.
        </p>
      </div>
    </div>
  );
}
