import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Analyzer from './pages/Analyzer';
import Results from './pages/Results';
import About from './pages/About';
import AIImageDetection from './pages/AIImageDetection';
import SteganographyScanner from './pages/SteganographyScanner';
import FactChecker from './pages/FactChecker';
import ScanHistory from './pages/ScanHistory';
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

          {/* Steganography Scanner */}
          <Route path="/steganography" element={<SteganographyScanner />} />

          {/* Fact Checker */}
          <Route path="/fact-checker" element={<FactChecker />} />

          {/* Scan History */}
          <Route path="/history" element={<ScanHistory />} />

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
