import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ImageIcon } from '../components/Icons';

const LIMITATIONS_CONTENT = {
  title: 'Limitations & Guidance',
  summary:
    'Automated image analysis can be wrong. Compressed, edited or screenshotted images are especially hard to judge. Do not treat this as proof.',
  inconclusiveExplanation:
    'What "Inconclusive" means: The model did not attain the minimum confidence threshold (65%) or the visual signals were ambiguous between human and synthetic origin. Inconclusive outcomes require manual inspection and should not be relied upon as verification of authenticity or synthetic generation.',
  difficultFormats:
    'Flat graphics, posters, screenshots, compressed or edited images are especially hard to judge.',
};

export function LimitationsCard() {
  return (
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
        {LIMITATIONS_CONTENT.title}
      </h2>
      <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 10px' }}>
        {LIMITATIONS_CONTENT.summary}
      </p>
      <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.6, margin: 0 }}>
        <strong>What &quot;Inconclusive&quot; means:</strong>{' '}
        {LIMITATIONS_CONTENT.inconclusiveExplanation.replace('What "Inconclusive" means: ', '')}{' '}
        {LIMITATIONS_CONTENT.difficultFormats}
      </p>
    </div>
  );
}

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

function validateFile(file) {
  if (!file) {
    return 'Please select an image first.';
  }
  if (file.size === 0) {
    return 'The selected image file is empty. Please choose a valid image.';
  }
  if (file.size > MAX_FILE_SIZE) {
    return 'The selected image exceeds the 5 MB limit. Please choose a smaller image.';
  }
  const isTypeValid = file.type && ALLOWED_TYPES.includes(file.type.toLowerCase());
  const name = file.name ? file.name.toLowerCase() : '';
  const isExtValid = ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext));
  if (!isTypeValid && !isExtValid) {
    return 'Unsupported file format. Please upload a JPEG, PNG, or WebP image.';
  }
  return null;
}

export default function AIImageDetection() {
  const [image, setImage] = useState(null);
  const [preview, setPreview] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef(null);
  const navigate = useNavigate();

  const handleFileSelect = useCallback((file) => {
    if (!file) return;
    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError('');
    setImage(file);
    setPreview((prev) => {
      if (prev) {
        URL.revokeObjectURL(prev);
      }
      return URL.createObjectURL(file);
    });
  }, []);

  const handleRemove = (e) => {
    if (e) e.stopPropagation();
    setPreview((prev) => {
      if (prev) {
        URL.revokeObjectURL(prev);
      }
      return null;
    });
    setImage(null);
    setError('');
    if (fileRef.current) {
      fileRef.current.value = '';
    }
  };

  useEffect(() => {
    const handlePaste = (e) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.type && item.type.startsWith('image/')) {
          const file = item.getAsFile();
          if (file) {
            handleFileSelect(file);
            break;
          }
        }
      }
    };
    window.addEventListener('paste', handlePaste);
    return () => {
      window.removeEventListener('paste', handlePaste);
    };
  }, [handleFileSelect]);

  const handleAnalyze = async () => {
    if (!image) {
      setError('Please select an image first.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('image', image);

      const response = await fetch('http://127.0.0.1:5000/analyze-image', {
        method: 'POST',
        body: formData,
      });

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

      navigate('/ai-image-results', {
        state: {
          result: data,
          image,
          imageUrl: preview,
          filename: image.name || 'Pasted Image',
        },
      });
    } catch (err) {
      if (
        err.name === 'TypeError' ||
        err.message.includes('fetch') ||
        err.message.includes('NetworkError') ||
        err.message.includes('Failed to fetch')
      ) {
        setError('Unable to connect to the backend server. Please verify the service is running.');
      } else {
        setError(err.message || 'Unable to connect to the backend.');
      }
    } finally {
      setLoading(false);
    }
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

      {/* Upload Card */}
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

        {/* Dropzone */}
        <div
          role="button"
          tabIndex={0}
          aria-label="Upload image"
          onClick={() => fileRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              fileRef.current?.click();
            }
          }}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const droppedFile = e.dataTransfer.files?.[0];
            if (droppedFile) handleFileSelect(droppedFile);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          style={{
            border: `2px dashed ${dragOver ? '#6366f1' : 'rgba(99, 102, 241, 0.25)'}`,
            borderRadius: 12,
            padding: '32px 20px',
            textAlign: 'center',
            cursor: 'pointer',
            background: dragOver ? 'rgba(99, 102, 241, 0.05)' : '#faf9ff',
            transition: 'all 0.2s',
            outline: 'none',
          }}
        >
          {preview ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <img
                src={preview}
                alt="Selected preview"
                style={{
                  maxHeight: 180,
                  maxWidth: '100%',
                  objectFit: 'contain',
                  borderRadius: 8,
                  marginBottom: 12,
                  border: '1px solid rgba(99, 102, 241, 0.15)',
                }}
              />
              <p style={{ fontSize: 13.5, fontWeight: 600, color: '#0f172a', margin: '0 0 4px' }}>
                {image?.name || 'Pasted image'}
              </p>
              {image?.size && (
                <span style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>
                  {(image.size / (1024 * 1024)).toFixed(2)} MB
                </span>
              )}
              <span style={{ fontSize: 12, color: '#6366f1', fontWeight: 600, marginBottom: 8 }}>
                Click or drag to replace image
              </span>
              <button
                type="button"
                onClick={handleRemove}
                style={{
                  padding: '4px 12px',
                  fontSize: 12,
                  fontWeight: 600,
                  color: '#dc2626',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
              >
                Remove
              </button>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 10, color: '#6366f1' }}>
                <ImageIcon size={36} color="#6366f1" />
              </div>
              <p style={{ fontSize: 13.5, fontWeight: 600, color: '#334155', margin: '0 0 4px' }}>
                Drag and drop an image here, click to browse, or paste one (Ctrl+V)
              </p>
              <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>
                Supports JPEG, PNG, WebP up to 5 MB
              </p>
            </div>
          )}
        </div>

        <input
          ref={fileRef}
          type="file"
          accept="image/jpeg,image/png,image/webp"
          style={{ display: 'none' }}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFileSelect(f);
            e.target.value = '';
          }}
        />

        <div style={{ marginTop: 18 }}>
          <button
            onClick={handleAnalyze}
            disabled={!image || loading}
            className="btn-primary"
            style={{
              padding: '10px 24px',
              fontSize: 14,
              fontWeight: 700,
              cursor: !image || loading ? 'not-allowed' : 'pointer',
              opacity: !image || loading ? 0.6 : 1,
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

        {/* Inline Error Message */}
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

      {/* Limitations Card (Before Analysis) */}
      <LimitationsCard />
    </div>
  );
}
