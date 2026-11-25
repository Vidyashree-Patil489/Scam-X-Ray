import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Analyzer from './pages/Analyzer';
import Results from './pages/Results';
import About from './pages/About';
import AIImageDetection from './pages/AIImageDetection';
import AIImageResults from './pages/AIImageResults';


import SecurityAwareness from './pages/SecurityAwareness';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* ─────────────────────────────────────────────────────────────
            A. PUBLIC LANDING PAGE (Route '/')
            Stand-alone experience without sidebar or app header.
        ───────────────────────────────────────────────────────────── */}
        <Route path="/" element={<Home />} />

        {/* ─────────────────────────────────────────────────────────────
            B. APPLICATION DASHBOARD & INTERNAL TOOLS (Wrapped in Layout)
            Includes the persistent collapsible sidebar and app navbar.
        ───────────────────────────────────────────────────────────── */}
        <Route element={<Layout />}>
          {/* Dashboard Homepage */}
          <Route path="/dashboard" element={<Dashboard />} />

          {/* Scam Detection Suite (both /scam-detection and backward-compatible /analyzer) */}
          <Route path="/scam-detection" element={<Analyzer />} />
          <Route path="/analyzer" element={<Analyzer />} />
          <Route path="/results" element={<Results />} />

          {/* AI Image Detection */}
          <Route path="/ai-image-detection" element={<AIImageDetection />} />
          <Route path="/ai-image-results" element={<AIImageResults />} />

          {/* Redirects for removed legacy tools so old bookmarks redirect gracefully */}
          <Route path="/steganography" element={<Navigate to="/dashboard" replace />} />
          <Route path="/fact-checker" element={<Navigate to="/dashboard" replace />} />
          <Route path="/history" element={<Navigate to="/dashboard" replace />} />

          {/* Security Awareness */}
          <Route path="/security-awareness" element={<SecurityAwareness />} />

          {/* Settings */}
          <Route path="/settings" element={<Settings />} />

          {/* About / System Info */}
          <Route path="/about" element={<About />} />

          {/* Fallback route */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

