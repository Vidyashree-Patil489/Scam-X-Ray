import test from 'node:test';
import assert from 'node:assert/strict';
import process from 'node:process';
import { createServer } from 'vite';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

let server;
let Sidebar;
let SecurityAwareness;
let App;
let Dashboard;
let Home;
let Settings;
let AIImageDetection;
let AIImageResults;

test.before(async () => {
  server = await createServer({
    root: process.cwd(),
    server: { middlewareMode: true },
  });
  const sidebarMod = await server.ssrLoadModule('./src/components/Sidebar.jsx');
  Sidebar = sidebarMod.default;

  const awarenessMod = await server.ssrLoadModule('./src/pages/SecurityAwareness.jsx');
  SecurityAwareness = awarenessMod.default;

  const appMod = await server.ssrLoadModule('./src/App.jsx');
  App = appMod.default;

  const dashMod = await server.ssrLoadModule('./src/pages/Dashboard.jsx');
  Dashboard = dashMod.default;

  const homeMod = await server.ssrLoadModule('./src/pages/Home.jsx');
  Home = homeMod.default;

  const settingsMod = await server.ssrLoadModule('./src/pages/Settings.jsx');
  Settings = settingsMod.default;

  const detectionMod = await server.ssrLoadModule('./src/pages/AIImageDetection.jsx');
  AIImageDetection = detectionMod.default;

  const resultsMod = await server.ssrLoadModule('./src/pages/AIImageResults.jsx');
  AIImageResults = resultsMod.default;
});

test.after(async () => {
  if (server) {
    await server.close();
  }
});

test('Sidebar navigation excludes removed pages and keeps allowed 5 in order', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/dashboard'] },
      React.createElement(Sidebar, {
        collapsed: false,
        setCollapsed: () => {},
        mobileOpen: false,
        setMobileOpen: () => {},
      })
    )
  );

  // Must NOT contain removed items
  assert.equal(html.includes('Fact Checker'), false, 'Must not contain Fact Checker');
  assert.equal(html.includes('Steganography Scanner'), false, 'Must not contain Steganography Scanner');
  assert.equal(html.includes('Scan History'), false, 'Must not contain Scan History');
  assert.equal(html.includes('/fact-checker'), false, 'Must not contain /fact-checker route');
  assert.equal(html.includes('/steganography'), false, 'Must not contain /steganography route');
  assert.equal(html.includes('/history'), false, 'Must not contain /history route');

  // Must contain the allowed 5 pages in current order
  assert.equal(html.includes('Dashboard'), true);
  assert.equal(html.includes('Scam Detection'), true);
  assert.equal(html.includes('AI Image Detection'), true);
  assert.equal(html.includes('Security Awareness'), true);
  assert.equal(html.includes('Settings'), true);

  const idxDashboard = html.indexOf('Dashboard');
  const idxScam = html.indexOf('Scam Detection');
  const idxAI = html.indexOf('AI Image Detection');
  const idxSecurity = html.indexOf('Security Awareness');
  const idxSettings = html.indexOf('Settings');

  assert.ok(idxDashboard < idxScam, 'Dashboard before Scam Detection');
  assert.ok(idxScam < idxAI, 'Scam Detection before AI Image Detection');
  assert.ok(idxAI < idxSecurity, 'AI Image Detection before Security Awareness');
  assert.ok(idxSecurity < idxSettings, 'Security Awareness before Settings');
});

test('Security Awareness page renders all required educational content sections', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(SecurityAwareness)
  );

  // Section 1: Common scams in India
  assert.ok(html.includes('Common Scams in India'));
  assert.ok(html.includes('work-from-home'));
  assert.ok(html.includes('task-based'));
  assert.ok(html.includes('KYC'));
  assert.ok(html.includes('Phishing links'));
  assert.ok(html.includes('QR-code'));
  assert.ok(html.includes('customer-care'));
  assert.ok(html.includes('Digital arrest'));

  // Section 2: Fake job offer red flags
  assert.ok(html.includes('Fake Job Offer Red Flags'));
  assert.ok(html.includes('Upfront fees') || html.includes('registration'));
  assert.ok(html.includes('WhatsApp or Telegram'));
  assert.ok(html.includes('No formal interview') || html.includes('No interview'));
  assert.ok(html.includes('free email') || html.includes('Gmail'));

  // Section 3: Never share
  assert.ok(html.includes('Never Share'));
  assert.ok(html.includes('OTP'));
  assert.ok(html.includes('UPI PIN'));
  assert.ok(html.includes('CVV'));
  assert.ok(html.includes('You never need to enter your UPI PIN to receive money'));

  // Section 4: Before you click
  assert.ok(html.includes('Before You Click'));
  assert.ok(html.includes('full domain'));
  assert.ok(html.includes('lookalike'));

  // Section 5: If you have been scammed (ordered steps)
  assert.ok(html.includes('If You Have Been Scammed'));
  assert.ok(html.includes('1930'), 'Helpline 1930 must be present');
  assert.ok(html.includes('cybercrime.gov.in'), 'cybercrime.gov.in must be present');
  assert.ok(html.includes('Do not delete the chat'));

  // Section 6: Report suspicious messages
  assert.ok(html.includes('Chakshu'));
  assert.ok(html.includes('sancharsaathi.gov.in/sfc'));

  // Section 7: Using ScamXRay responsibly
  assert.ok(html.includes('Using ScamXRay Responsibly'));
  assert.ok(html.includes('No threat found'));

  // Links must open in a new tab
  assert.ok(html.includes('href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer"'));
  assert.ok(html.includes('href="https://sancharsaathi.gov.in/sfc" target="_blank" rel="noopener noreferrer"'));
});

test('App routes and components load without removed pages', () => {
  assert.ok(App);
});

test('Dashboard renders only Scam Detection and AI Image Detection tools, no Recent Activity widget', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/dashboard'] },
      React.createElement(Dashboard)
    )
  );

  // Tool cards
  assert.ok(html.includes('Scam Detection'));
  assert.ok(html.includes('AI Image Detection'));
  assert.equal(html.includes('Steganography Scanner'), false);
  assert.equal(html.includes('Fact Checker'), false);

  // Quick Access
  assert.ok(html.includes('Quick Access'));
  assert.ok(html.includes('Security Awareness'));
  assert.ok(html.includes('Settings'));
  assert.ok(html.includes('Engine status and privacy information'));
  assert.equal(html.includes('Scan History'), false);

  // Recent Activity - entire widget removed
  assert.equal(html.includes('Recent Activity'), false);
  assert.equal(html.includes('View All History'), false);
  assert.equal(html.includes('No previous scan records yet'), false);
  assert.equal(html.includes('Completed investigations across all four threat engines will be automatically archived here.'), false);
});

test('Home page renders updated copy, 2 detection engines, updated hero stats, and no removed features', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/'] },
      React.createElement(Home)
    )
  );

  // Hero
  assert.ok(html.includes('From suspicious messages and links to AI-generated images, ScamXRay brings powerful digital threat analysis tools together in one place.'));
  assert.ok(html.includes('>2<') && html.includes('Detection Engines'));
  assert.equal(html.includes('Forensic Modules'), false);

  // Updated hero stats
  assert.ok(html.includes('>0<') && html.includes('Accounts Required'));
  assert.equal(html.includes('Privacy Focused'), false);
  assert.ok(html.includes('>Fast<') && html.includes('Rule-Based Checks'));
  assert.equal(html.includes('Local Heuristics'), false);

  // Floating tags
  assert.equal(html.includes('Hidden Payload Check'), false);
  assert.ok(html.includes('Threat Detected'));
  assert.ok(html.includes('Suspicious URL'));
  assert.ok(html.includes('AI Media Analysis'));

  // Section heading and subtitle
  assert.ok(html.includes('One Platform. Two Layers of Digital Protection.'));
  assert.equal(html.includes('Four Layers'), false);
  assert.ok(html.includes('A centralized digital safety platform designed to identify deceptive interactions across communications and media.'));

  // Tool cards in Home
  assert.ok(html.includes('Scam Detection'));
  assert.ok(html.includes('AI Image Detection'));
  assert.equal(html.includes('Steganography Scanner'), false);
  assert.equal(html.includes('Fact Checker'), false);

  // How ScamXRay Works steps
  assert.ok(html.includes('Paste suspicious text, submit a link, or upload an image file.'));
  assert.ok(html.includes('The dedicated engine analyzes heuristic rules, ML models, URL checks, or image signals.'));

  // Why Consolidate Threat Verification cards
  assert.ok(html.includes('Modern digital attacks rarely rely on a single vector. Fraudsters combine smishing, deceptive links, and synthetic media to build false credibility.'));
  assert.ok(html.includes('Verify an internship message, scan its included link, and inspect an attached poster screenshot without juggling separate disjointed tools.'));
  assert.ok(html.includes('Rather than returning an opaque black-box score, ScamXRay outlines exact matched heuristic rules, URL checks, or image-analysis signals.'));
  assert.ok(html.includes('Scans operate without mandatory user tracking or credentials. No account or sign-in is needed to run a scan.'));

  // CTA
  assert.ok(html.includes('Access both digital threat intelligence engines instantly in your browser.'));

  // Footer
  assert.ok(html.includes('Intelligent digital safety platform unifying scam detection and synthetic media analysis.'));
  assert.equal(html.includes('forensic steganography'), false);
  assert.equal(html.includes('factual claim verification'), false);
});

test('Settings page renders all informational sections, engine status, and privacy architecture', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/settings'] },
      React.createElement(Settings)
    )
  );

  // Header
  assert.ok(html.includes('Platform Settings'));

  // Section 1: Engine status
  assert.ok(html.includes('Engine Ready'));
  assert.ok(html.includes('Engine Status'));

  // Section 2: What ScamXRay checks
  assert.ok(html.includes('What ScamXRay Checks'));
  assert.ok(html.includes('Text and messages:'));
  assert.ok(html.includes('Links:'));
  assert.ok(html.includes('Screenshots:'));
  assert.ok(html.includes('OpenPhish'));
  assert.ok(html.includes('Malicious'));
  assert.ok(html.includes('Suspicious'));
  assert.ok(html.includes('No threat found'));
  assert.ok(html.includes('Unknown'));

  // Section 3: Privacy and data
  assert.ok(html.includes('Privacy and Data Handling'));
  assert.ok(html.includes('What is sent to our backend:'));
  assert.ok(html.includes('External AI service:'));
  assert.ok(html.includes('Groq'));
  assert.ok(html.includes('openai/gpt-oss-20b'));
  assert.ok(html.includes('URL scan network requests:'));
  assert.ok(html.includes('rdap.org'));
  assert.ok(html.includes('openphish.com'));
  assert.ok(html.includes('No accounts or sign-in:'));
  assert.ok(html.includes('Scan results are not stored:'));

  // Section 4: Limits of automated analysis
  assert.ok(html.includes('Limits of Automated Analysis'));
  assert.ok(html.includes('Advisory nature:'));
  assert.ok(html.includes('No safety guarantee:'));
  assert.ok(html.includes('Verify with official sources:'));

  // Section 5: About ScamXRay
  assert.ok(html.includes('About ScamXRay'));
  assert.ok(html.includes('href="/security-awareness"'));
});

test('AIImageDetection page renders dropzone instructions and limitations card', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/ai-image-detection'] },
      React.createElement(AIImageDetection)
    )
  );

  // Dropzone text
  assert.ok(html.includes('Drag and drop an image here, click to browse, or paste one (Ctrl+V)'));
  assert.ok(html.includes('Supports JPEG, PNG, WebP up to 5 MB'));

  // Limitations card before analysis
  assert.ok(html.includes('Limitations &amp; Guidance') || html.includes('Limitations & Guidance'));
  assert.ok(html.includes('Automated image analysis can be wrong. Compressed, edited or screenshotted images are especially hard to judge. Do not treat this as proof.'));
  assert.ok(html.includes('What &quot;Inconclusive&quot; means:') || html.includes('What "Inconclusive" means:'));
});

test('AIImageResults page renders all sections for Likely AI-generated, Likely human-created, and Inconclusive', () => {
  // Test Case 1: Likely AI-generated
  const stateAI = {
    result: {
      success: true,
      result: 'Likely AI-generated',
      label: 'AI-generated',
      confidence: 94.2,
      all_predictions: [
        { label: 'AI-generated', confidence: 94.2 },
        { label: 'human', confidence: 5.8 },
      ],
    },
    filename: 'suspicious_portrait.png',
  };

  const htmlAI = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: [{ pathname: '/ai-image-results', state: stateAI }] },
      React.createElement(AIImageResults)
    )
  );

  // Section a: Header
  assert.ok(htmlAI.includes('AI Image Detection Report'));
  assert.ok(htmlAI.includes('Analyze another image'));
  assert.ok(htmlAI.includes('Back to Image Detection'));

  // Section b: Verdict card
  assert.ok(htmlAI.includes('Detection Verdict'));
  assert.ok(htmlAI.includes('Likely AI-generated'));
  assert.ok(htmlAI.includes('94.2%'));
  assert.ok(htmlAI.includes('AI-generated'));
  assert.ok(htmlAI.includes('Human-created'));

  // Section c: What this result means
  assert.ok(htmlAI.includes('What This Result Means'));
  assert.ok(htmlAI.includes('The model estimates a 94.2% probability that this image is AI-generated. It does not show which parts of the image led to this result.'));
  assert.ok(htmlAI.includes('65%'));

  // Section d: What to look for
  assert.ok(htmlAI.includes('What to Look for in Images'));
  assert.ok(htmlAI.includes('Look closely'));
  assert.ok(htmlAI.includes('Check the source'));

  // Section e: How this was analysed
  assert.ok(htmlAI.includes('How This Was Analysed'));
  assert.ok(htmlAI.includes('https://huggingface.co/aaronkantrowitz/ai-human-generated-image-detection'));
  assert.ok(htmlAI.includes('Your image was sent to the ScamXRay server, analysed in memory and not stored.'));

  // Section f: Limitations card
  assert.ok(htmlAI.includes('Limitations &amp; Guidance') || htmlAI.includes('Limitations & Guidance'));
  assert.ok(htmlAI.includes('Automated image analysis can be wrong. Compressed, edited or screenshotted images are especially hard to judge. Do not treat this as proof.'));

  // Test Case 2: Likely human-created
  const stateHuman = {
    result: {
      success: true,
      result: 'Likely human-created',
      label: 'human',
      confidence: 91.5,
      all_predictions: [
        { label: 'human', confidence: 91.5 },
        { label: 'AI-generated', confidence: 8.5 },
      ],
    },
    filename: 'team_photo.jpg',
  };

  const htmlHuman = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: [{ pathname: '/ai-image-results', state: stateHuman }] },
      React.createElement(AIImageResults)
    )
  );

  assert.ok(htmlHuman.includes('Likely human-created'));
  assert.ok(htmlHuman.includes('The model estimates a 91.5% probability that this image is human-created. This does not prove the image is authentic or unedited.'));

  // Test Case 3: Inconclusive
  const stateInconclusive = {
    result: {
      success: true,
      result: 'Inconclusive',
      label: 'AI-generated',
      confidence: 58.0,
      all_predictions: [
        { label: 'AI-generated', confidence: 58.0 },
        { label: 'human', confidence: 42.0 },
      ],
    },
    filename: 'blurry_badge.jpg',
  };

  const htmlInconclusive = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: [{ pathname: '/ai-image-results', state: stateInconclusive }] },
      React.createElement(AIImageResults)
    )
  );

  assert.ok(htmlInconclusive.includes('Inconclusive'));
  assert.ok(
    htmlInconclusive.includes("The model's confidence was below 65%, so the result is not reliable either way. Treat it as unverified and check the image manually.") ||
    htmlInconclusive.includes("The model&#x27;s confidence was below 65%, so the result is not reliable either way. Treat it as unverified and check the image manually.")
  );
});

test('AIImageResults page redirects without state', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/ai-image-results'] },
      React.createElement(AIImageResults)
    )
  );

  // Without state, the report must not be rendered
  assert.equal(html.includes('AI Image Detection Report'), false);
  assert.equal(html.includes('Detection Verdict'), false);
});

test('AI Image pages do not make proof-style claims in rendered text', () => {
  const stateAI = {
    result: {
      success: true,
      result: 'Likely AI-generated',
      label: 'AI-generated',
      confidence: 94.2,
      all_predictions: [
        { label: 'AI-generated', confidence: 94.2 },
        { label: 'human', confidence: 5.8 },
      ],
    },
    filename: 'test.jpg',
  };

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: [{ pathname: '/ai-image-results', state: stateAI }] },
      React.createElement(AIImageResults)
    )
  );

  // Must disclaim proof
  assert.ok(html.includes('Do not treat this as proof'));
  assert.ok(html.includes('This does not prove') || html.includes('does not show which parts'));

  // Must not claim conclusive proof or guarantee
  assert.equal(html.includes('conclusive proof'), false);
  assert.equal(html.includes('definitively proved'), false);
  assert.equal(html.includes('guaranteed authentic'), false);
});
