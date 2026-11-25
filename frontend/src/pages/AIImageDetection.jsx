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
          body: formData
        }
      );

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Image analysis failed.');
      }

      setResult(data);

    } catch (err) {
      setError(err.message || 'Unable to connect to the backend.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="image-detection-page">

      <h1>AI Image Detection</h1>

      <p>
        Upload an image to check whether it is likely
        AI-generated or human-created.
      </p>

      <div className="image-upload-box">

        <input
          type="file"
          accept="image/jpeg,image/png,image/webp"
          onChange={handleImageChange}
        />

        {preview && (
          <div>
            <h3>Image Preview</h3>
            <img
              src={preview}
              alt="Uploaded preview"
              style={{
                maxWidth: '300px',
                maxHeight: '300px',
                objectFit: 'contain'
              }}
            />
          </div>
        )}

        <br />

        <button
          onClick={handleAnalyze}
          disabled={!image || loading}
        >
          {loading ? 'Analyzing Image...' : 'Analyze Image'}
        </button>

      </div>

      {error && (
        <p style={{ color: 'red' }}>
          {error}
        </p>
      )}

      {result && (
        <div className="image-result">

          <h2>Detection Result</h2>

          <h3>{result.result}</h3>

          <p>
            Confidence: {result.confidence}%
          </p>

          <p>
            Model Label: {result.label}
          </p>

        </div>
      )}

    </div>
  );
}