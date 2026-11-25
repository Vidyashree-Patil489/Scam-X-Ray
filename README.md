# ScamXRay

Multi-layer threat intelligence and scam detection platform for digital messages, suspicious links, and job communications.

ScamXRay is designed for students, job seekers, and everyday users to inspect suspicious recruitment notices, employment offers, unexpected messages, links, and screenshots before engaging or sharing sensitive information. It combines deterministic pattern matching, a machine learning classifier, URL infrastructure verification, and generative AI explanations into a unified analysis pipeline.

## Features

### Multi-Layer Scam Detection

ScamXRay analyzes input across three distinct channels:

- **Text and Message Analysis**: Evaluates job descriptions, SMS messages, and emails against known fraud patterns.
- **URL Analysis**: Performs syntactic and live infrastructure checks against web links.
- **Screenshot Analysis**: Uses client-side Optical Character Recognition (OCR) powered by Tesseract.js directly inside the user's browser. The extracted text is then routed through the text analysis pipeline. The image itself is never sent to the server.

For text and OCR inputs, ScamXRay evaluates content through three detection layers:

1. **Heuristic Rule Engine**: Deterministic regular expressions identifying high-risk recruitment signals, including upfront application fees, OTP/PIN/CVV requests, unrealistic salaries, suspicious contact methods (such as personal Gmail addresses or WhatsApp-only recruitment), withheld interview venues, and artificial urgency.
2. **Machine Learning Classifier**: A TF-IDF vectorizer paired with a Logistic Regression classifier trained on recruitment fraud data to assess text probability patterns.
3. **AI Threat Assessment**: An LLM call via the Groq API (`openai/gpt-oss-20b`) that reviews the text and detected flags to generate a plain-language summary and actionable safety advice. The model prompt explicitly restricts the LLM from making claims about visual elements (such as logos, stamps, or document styling) that plain text cannot verify.

#### Composite Scoring and Evidence Floor

For text and OCR analyses, ScamXRay calculates an overall composite risk score (0 to 100) using weighted aggregation:

- Rule Engine: 40%
- AI Assessment: 35%
- ML Classifier: 25%

If any layer is unavailable (for example, if the Groq API key is missing or encounters a rate limit), weights are automatically renormalized across the available layers.

To prevent high-confidence deterministic indicators from being diluted by statistical or generative models, ScamXRay enforces an **Evidence Floor**:
- When the Rule Engine score is 75 or higher (indicating multiple severe fraud indicators or direct payment demands), the composite score cannot fall below 75 and cannot fall below the Rule Engine score.
- When an accompanying URL is analyzed alongside text, the overall risk score is at least the URL threat score (`max(composite_score, url_score)`).

Risk scores map to four risk levels:
- **Low**: 0 to 30
- **Medium**: 31 to 70
- **High**: 71 to 100

### URL Analysis and Infrastructure Verification

When a URL is submitted, ScamXRay executes a dedicated URL threat inspection pipeline with four possible verdicts:

- **Malicious**: Confirmed active threat identified in community threat intelligence feeds (threat score: 100).
- **Suspicious**: Identified structural deception indicators (threat score: 35 to 100).
- **No threat found**: Passed all infrastructure verification checks with zero threat indicators (threat score: 0).
- **Unknown**: Verification checks failed, timed out, were not performed, target a user-content platform, or involve an RFC reserved domain.

The URL inspection pipeline evaluates indicators and infrastructure through:

- **OpenPhish Community Feed Lookup**: Compares target URLs and domains against the public OpenPhish feed with local caching (12-hour refresh interval). A match triggers `openphish_reputation_match` (`critical` severity, 100 points), immediately assigning a `Malicious` verdict and a threat score of 100.
- **Structural Threat Indicators**:
  - `userinfo_trick` (`critical`, 70 points): URL contains user authentication syntax (`@`), disguising the true destination host.
  - `brand_lookalike_domain` (`critical`, 70 points): Registered domain combines a known brand name with a security/action keyword (e.g., `login`, `verify`, `kyc`) or uses a 1-edit near-miss substitution (for brand tokens of 6 or more characters).
  - `subdomain_brand_spoof` (`critical`, 70 points): Subdomain contains a known brand while registered under an unrelated domain (e.g. `paypal.com.evil.com`).
  - `brand_lookalike_domain` (`high`, 35 points): Registered domain incorporates an unambiguous brand name without official affiliation.
  - `homoglyph_punycode` (`high`, 35 points): Hostname uses Internationalized Domain Name / Punycode syntax (`xn--`), often used for visually deceptive character swaps.
  - `ip_literal_host` (`high`, 35 points): URL points directly to a public IP address literal rather than a domain name.
  - `executable_download` (`high`, 35 points): URL path requests direct download of executable or archive payloads (`.exe`, `.scr`, `.bat`, `.cmd`, `.msi`, `.apk`, `.vbs`, `.iso`, `.dmg`, `.jar`, `.zip`, `.rar`, `.7z`, `.tar.gz`, `.hta`, `.wsf`, `.ps1`).
  - `new_domain` (`medium`, 25 points if < 7 days; 15 points if 7 to 29 days): Domain registered recently according to RDAP query.
  - `external_redirect_param` (`medium`, 20 points): Query string contains an open redirect parameter (`next`, `url`, `redirect`, `dest`, etc.) pointing to an external registrable domain.
  - `url_shortener` (`medium`, 15 points): Public link shortener (`bit.ly`, `tinyurl.com`, `t.ly`, etc.) that conceals the true destination.
  - `http_credentials` (`medium`, 15 points): Unencrypted plain HTTP protocol used for sensitive authentication or payment endpoints.
  - `excessive_subdomains` (`medium`, 15 points): Hostname exhibits 3 or more nested subdomain levels.
  - `excessive_length_obfuscation` (`medium`, 15 points): URL exceeds 120 characters with 5 or more percent-encoded tokens (`%xx`).
  - `suspicious_tld` (`info`, 0 points): Uncommon top-level domain (`.xyz`, `.top`, `.click`, `.loan`, `.work`, `.zip`, `.mov`, etc.). **Informational only; does not add points and does not affect the verdict or score on its own.**
  - `user_content_platform` (`info`, 0 points): Hostname is a shared user-content host (`github.io`, `vercel.app`, `netlify.app`, `docs.google.com`, etc.). Informational only; because platform reputation cannot attest to individual user-created pages, URLs on these hosts default to an `Unknown` verdict if no threat indicators exist.
- **Verification Checks**: Concurrently evaluates DNS resolution, TLS certificate validity and hostname matching, domain registration age via public RDAP (`rdap.org`), and HTTP reachability across redirects:
  - **Domain Age Threshold**: The RDAP check evaluates registration age in days. Domains registered strictly more than 365 days ago are classified as established (`is_established = True`). Domains registered 365 days ago or less are not considered established (`is_established = False`). An established domain age (> 365 days) is a mandatory condition for the "No threat found" verdict. Domains between 30 and 365 days old trigger no threat indicator points, but resolve to an `Unknown` verdict because positive verification evidence is incomplete.
- **Server-Side Request Forgery (SSRF) Protection**: Strict validation blocks connections to private, loopback, link-local, multicast, cloud metadata (e.g. `169.254.169.254`), and internal network addresses across dotted-decimal, decimal integer, octal, hexadecimal, and IPv6 representations. Every redirect hop is independently validated before following.
- **Failed Checks Never Raise Threat Level**: If network verification checks time out, cannot resolve, or fail due to server network limitations, the system returns `Unknown` rather than flagging the target as suspicious or malicious. A `No threat found` verdict requires all verification checks to complete successfully with zero indicators.

### Risk Phrase Highlighting and Flag Detection

The analysis response includes exact character offset spans (`[start, end]`) for each rule match. The frontend highlights these exact phrases within the original text and displays a categorized list of all identified threat flags.

### Security Awareness and Settings

- **Security Awareness Guide**: Cyber safety guidance tailored to users in India, organized into six practical sections:
  1. **Emergency Help & Reporting**: Contact cards providing direct access to the national financial fraud helpline **1930** (toll-free 24x7 assistance to freeze victim accounts), the National Cyber Crime Reporting Portal ([cybercrime.gov.in](https://cybercrime.gov.in)), and the Department of Telecommunications' Sanchar Saathi Chakshu facility ([sancharsaathi.gov.in/sfc](https://sancharsaathi.gov.in/sfc)) for reporting suspicious calls, SMS, or WhatsApp messages before financial loss occurs.
  2. **Common Scams in India**: Prevalent fraud tactics targeting individuals, including fake job offers (unsolicited work-from-home and task-based scams such as liking videos or rating products), urgent fake KYC/bank messages threatening account or SIM deactivation, phishing links masquerading as services or lotteries, UPI "Collect Request" and QR-code tricks where scammers request PINs under the pretext of sending money, fake customer-care support numbers on search engines and social media, and impersonation of police, CBI, customs, or court officials (highlighting that "digital arrest" is an absolute scam, as no genuine agency conducts arrests over video calls or demands money to settle investigations).
  3. **Fake Job Offer Red Flags**: Common warning signs of recruitment fraud, including demands for upfront fees (registration, processing, training materials, onboarding kits, or "refundable" security deposits), unrealistic salary offers for minimal work, informal communication exclusively through WhatsApp or Telegram, artificial urgency demanding action within hours, immediate job offers issued without formal interviews or evaluations, recruiters contacting from free email services (Gmail, Yahoo, Outlook), and vague company details with missing physical office addresses or websites.
  4. **Never Share**: Clear guidance on credentials that must never be shared (OTP, UPI PIN, card PIN or CVV, and account passwords), emphasizing the Golden Rule: a UPI PIN is only entered when transferring money out of an account, never to receive money.
  5. **Before You Click**: Practical link inspection habits: checking the full domain name rather than deceptive subdomains, looking for character-substitution typosquatting (such as the digit `1` for `l` or `0` for `o`), exercising caution with shortened URLs (`bit.ly`, `tinyurl`), and navigating directly to official sites rather than following links in unsolicited messages.
  6. **If You Have Been Scammed (Steps, in Order)**: Step-by-step emergency response instructions: Step 1: Immediately contact your bank or payment provider to freeze accounts and cards; Step 2: Report financial fraud via national helpline 1930 or `cybercrime.gov.in`; Step 3: Collect and preserve digital evidence (screenshots, transaction UTR/reference numbers, payment receipts, bank statements, phone numbers); Step 4: Retain the full unaltered chat history for investigating authorities.
  7. **Using ScamXRay Responsibly**: Guidance reminding users that automated analysis is advisory, "No threat found" is not a safety guarantee, and offers should always be confirmed directly with official organizations.
- **Settings Page**: An informational view detailing the operational status of analysis engines, system architecture, data privacy handling, and analysis boundaries.

### AI Image Detection

- **Status: Planned / Placeholder**. The user interface contains a placeholder view (`/ai-image-detection`) marked for Stage 6. No backend image classification or synthetic media detection model is currently active.

## How It Works

ScamXRay uses a decoupled client-server architecture. The React frontend handles user interactions and local OCR processing, while the Python Flask backend executes the multi-layered analysis pipeline.

```
┌────────────────────────────────────────────────────────┐
│                   React Frontend                       │
│  - Text input, URL input, or client-side Tesseract OCR │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ HTTP POST /analyze
                            ▼
┌────────────────────────────────────────────────────────┐
│                    Flask Backend                       │
│                                                        │
│  ┌───────────────────┐        ┌─────────────────────┐  │
│  │ URL Scan Path     │        │ Text / OCR Scan Path│  │
│  ├───────────────────┤        ├─────────────────────┤  │
│  │ 1. OpenPhish Feed │        │ 1. Heuristic Rules  │  │
│  │ 2. Structural Cues│        │ 2. Scikit-learn ML  │  │
│  │ 3. DNS / TLS /    │        │ 3. Groq LLM API     │  │
│  │    RDAP / HTTP    │        │ 4. Composite Score  │  │
│  │ 4. Verdict Engine │        │    + Evidence Floor │  │
│  └─────────┬─────────┘        └──────────┬──────────┘  │
│            │                             │             │
│            └──────────────┬──────────────┘             │
│                           │                            │
│           Threat Categorization & Radar Model          │
└───────────────────────────┬────────────────────────────┘
                            │
                            │ JSON Response
                            ▼
┌────────────────────────────────────────────────────────┐
│                   React Frontend                       │
│  - Threat score badge, risk level, & radar chart       │
│  - Phrase highlight overlay from exact character spans │
│  - URL verification cards & actionable safety advice   │
└────────────────────────────────────────────────────────┘
```

## Tech Stack

### Frontend

- **Framework**: React 19 (`react`, `react-dom`)
- **Build Tool**: Vite 8 (`vite`, `@vitejs/plugin-react`)
- **Styling**: Tailwind CSS 4 (`tailwindcss`, `@tailwindcss/vite`)
- **Routing**: React Router 7 (`react-router-dom`)
- **Animations & Charts**: Framer Motion 12 (`framer-motion`), Recharts 3 (`recharts`)
- **Client-Side OCR**: Tesseract.js 7 (`tesseract.js`)
- **Code Quality**: ESLint 10 (`eslint`)
- **Testing**: Node.js test runner (`node --test`)

### Backend

- **Language**: Python 3.10+ (tested on Python 3.14)
- **Web Framework**: Flask 3.1.3 (`flask`), Flask-CORS 6.0.2 (`flask-cors`)
- **Machine Learning**: scikit-learn 1.7.2 (`scikit-learn`), NumPy
- **Generative AI**: Groq Python SDK 1.2.0 (`groq`) using `openai/gpt-oss-20b`
- **Domain & URL Inspection**: Requests 2.33.1 (`requests`), tldextract 5.4.0 (`tldextract`)
- **Environment Management**: python-dotenv 1.2.4 (`python-dotenv`)
- **Production Server**: Gunicorn 23.0.0 (`gunicorn`, for Linux deployments)
- **Testing**: Python standard library `unittest`

## Project Structure

```
Scam-X-Ray/
├── .env.example              # Template for root environment variables
├── .gitattributes            # Line ending normalization and binary file tracking
├── .gitignore                # Git ignore patterns for Python, Node, and secrets
├── README.md                 # Project documentation
├── backend/                  # Flask REST API and threat detection services
│   ├── .env.example          # Template for backend environment variables
│   ├── .gitignore            # Backend-specific ignore rules
│   ├── app.py                # Server entry point, endpoints, and scoring pipeline
│   ├── models/               # Serialized ML artifacts
│   │   ├── model.pkl         # Trained Logistic Regression classifier
│   │   └── vectorizer.pkl    # Trained TF-IDF vectorizer
│   ├── Procfile              # Process runner configuration for web deployments
│   ├── README.md             # Backend architecture documentation
│   ├── render.yaml           # Blueprint specification for Render deployment
│   ├── requirements.txt      # Pinned Python dependencies
│   ├── scripts/              # Development inspection and benchmarking utilities
│   ├── services/             # Core threat detection engines
│   │   ├── analyzer.py       # Groq LLM explanation and fallback handler
│   │   ├── category_classifier.py # Threat category and radar score mapper
│   │   ├── predictor.py      # ML fraud score inference
│   │   ├── reputation.py     # OpenPhish feed fetching and caching
│   │   ├── rule_engine.py    # Regex heuristic rule engine with span offsets
│   │   └── url_analyzer.py   # URL syntax indicators, SSRF guards, and network checks
│   └── tests/                # Automated backend test suite
│       ├── fixtures/         # Mock test payloads and responses
│       ├── test_regression.py # Regression test suite covering URLs, rules, and scoring
│       └── unit/             # Unit tests for domain correspondence
├── docs/                     # Documentation assets
│   └── screenshots/          # Application screenshot images
└── frontend/                 # React single-page application
    ├── .gitignore            # Frontend-specific ignore rules
    ├── eslint.config.js      # ESLint configuration
    ├── index.html            # Application entry HTML
    ├── package.json          # Frontend dependencies and npm scripts
    ├── package-lock.json     # Locked dependency versions
    ├── public/               # Static assets
    ├── README.md             # Frontend overview documentation
    ├── src/                  # React application source code
    │   ├── assets/           # Bundled image assets
    │   ├── components/       # Reusable UI components (Layout, Navbar, Sidebar)
    │   ├── hooks/            # Custom hooks (useOCR for in-browser OCR)
    │   ├── pages/            # Application pages (Home, Dashboard, Analyzer, Results, etc.)
    │   ├── App.jsx           # Route declarations
    │   ├── index.css         # Global styling and Tailwind imports
    │   └── main.jsx          # React application root
    ├── tests/                # Frontend tests executed with node --test
    └── vite.config.js        # Vite bundler configuration
```

## Getting Started

### Prerequisites

- **Python**: Version 3.10 or higher.
- **Node.js**: Version 18.0.0 or higher (Node 20+ recommended).
- **npm**: Version 9.0.0 or higher.
- **Groq API Key**: Optional, required for AI-generated threat explanations.

### Clone the Repository

Clone the project repository to your local system and enter the project folder:

```bash
git clone https://github.com/Vidyashree-Patil489/Scam-X-Ray.git
cd Scam-X-Ray
```

### Backend Setup

1. Open a terminal and navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   - **Windows PowerShell**:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. Install pinned Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   - **Windows PowerShell**:
     ```powershell
     Copy-Item .env.example .env
     ```
   - **macOS / Linux**:
     ```bash
     cp .env.example .env
     ```
   Open `.env` in an editor and insert your `GROQ_API_KEY` if available.

5. Start the backend development server:
   ```bash
   python app.py
   ```
   The backend starts at `http://127.0.0.1:5000`.

### Frontend Setup

1. Open a second terminal and navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install npm dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   The frontend runs by default at `http://localhost:5173`.

> [!NOTE]
> The frontend currently contains a hard-coded API endpoint (`const API_URL = 'http://127.0.0.1:5000/analyze'` in `frontend/src/pages/Analyzer.jsx`). It connects directly to the local backend on port 5000 during local development. If deploying the frontend to a remote hosting platform, this target URL must be updated to your deployed backend URL before building the production assets.

## Configuration

Environment variables read by the backend:

| Variable Name | Required | Purpose | Default / Behavior If Missing |
| :--- | :--- | :--- | :--- |
| `GROQ_API_KEY` | Optional | Authenticates with the Groq API to generate AI explanations using `openai/gpt-oss-20b`. | If missing, the app uses deterministic fallback explanations and safety tips. `llm_score` becomes `None` and composite weights renormalize. |
| `PORT` | Optional | Specifies the local TCP port on which the Flask development server listens. | Defaults to `5000`. |
| `FLASK_DEBUG` | Optional | Enables Flask debug mode when set to `"true"`. | Defaults to `false`. |

The frontend does not require any build-time or runtime environment variables.

## API Documentation

### GET /health

Health check endpoint used by uptime monitors and deployment platforms.

- **Method**: `GET`
- **Response**: `200 OK`
  ```json
  {
    "status": "ok"
  }
  ```

### POST /analyze

Primary threat evaluation endpoint for text, links, and screenshot OCR.

- **Method**: `POST`
- **Headers**: `Content-Type: application/json`

#### Request Body Fields

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `text` | string | Optional* | Message text, job notice, or extracted OCR content. |
| `url` | string | Optional* | Target link to inspect. Must begin with `http://` or `https://`. |
| `input_type` | string | Optional | Contextual type hint (e.g. `"text"`, `"url"`, or `"ocr"`). |

*\*At least one of `text` or `url` must be provided. Submitting neither returns `400 Bad Request`.*

#### Response Body Fields (`200 OK`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `risk_score` | integer | Overall calibrated threat score from 0 to 100. |
| `risk_level` | string | Risk classification: `"Low"`, `"Medium"`, `"High"`, or `"Unknown"`. |
| `verdict` / `url_verdict` | string \| null | URL evaluation outcome: `"Malicious"`, `"Suspicious"`, `"No threat found"`, or `"Unknown"` (null for text-only scans). |
| `url_verdict_reason` | string \| null | Deterministic explanation for the URL verdict. |
| `scam_category` | string | High-level categorization of the threat type. |
| `classification_criteria` | string[] | Specific criteria triggering the classification. |
| `radar_indicators` | object | Threat dimension scores (0–100): `urgency`, `payment`, `url_risk`, `ml_score`, and `impersonation`. |
| `explanation` | string | Plain-language risk explanation (LLM-generated or deterministic fallback). |
| `safety_tips` | string[] | Actionable safety recommendations for the user. |
| `rule_score` | integer \| null | Score from the heuristic rule engine (0–100). |
| `ml_score` | float \| null | Score from the machine learning classifier (0–100). |
| `url_score` | integer \| null | Structural threat score from the URL inspection (0–100). |
| `llm_score` | integer \| null | Score assigned by the AI model (null for URL-only scans). |
| `rule_flags` / `text_flags` | string[] | Array of heuristic warning descriptions detected in the text. |
| `url_flags` | string[] | Array of warning descriptions detected during URL evaluation. |
| `matches` / `flags` | object[] | Array of rule matches containing `rule`, `category`, `severity`, `evidence`, and exact character offsets `span: [start, end]`. |
| `indicators` | object[] \| null | Structured indicators detected in the URL (`id`, `severity`, `points`, `description`, `value`). |
| `verification_checks` | object[] \| null | Array of technical verification results covering DNS resolution, TLS certificate, domain age, and HTTP reachability. |
| `categories` | string[] | Matched heuristic rule categories (e.g. `"financial"`, `"urgency"`, `"suspicious_contact"`). |
| `text` / `jobText` | string | Sanitized input text. |
| `url` | string | Evaluated URL. |

## Running Tests

### Backend Tests

The backend test suite is built on Python's standard `unittest` framework. It verifies regex rule triggers, span offset calculations, SSRF defenses, URL indicators, domain correspondence, and composite score weighting.

To execute the backend suite from the project root:

- **Windows PowerShell**:
  ```powershell
  python -m unittest discover backend/tests
  ```
- **macOS / Linux**:
  ```bash
  python3 -m unittest discover backend/tests
  ```

### Frontend Tests

The frontend uses the Node.js built-in test runner alongside SSR component rendering to verify phrase highlight offsets, navigation routes, settings content, and results rendering.

To run the frontend suite from the frontend directory:

```bash
cd frontend
npm test
```

To run linting:

```bash
cd frontend
npm run lint
```

To run the production build:

```bash
cd frontend
npm run build
```

## Deployment

The repository includes preconfigured deployment specifications for web hosting:

- **`backend/render.yaml`**: A Render blueprint configuration defining a Python web service:
  - Build command: `pip install -r backend/requirements.txt`
  - Start command: `cd backend && python app.py`
  - Environment variable: `GROQ_API_KEY` (sync: false)
- **`backend/Procfile`**: Process definition for platforms utilizing Procfiles (e.g. Heroku or Render):
  - Command: `web: python app.py` (or Gunicorn via `gunicorn app:app`)

A deployment requires:
1. Python 3.10+ runtime.
2. `GROQ_API_KEY` environment variable configured in the host environment settings.
3. Node.js build pipeline for static hosting of the `frontend/dist` directory (e.g., via Vercel, Netlify, or Render Static Sites).

> [!IMPORTANT]
> The frontend single-page application currently has `const API_URL = 'http://127.0.0.1:5000/analyze'` hard-coded in `frontend/src/pages/Analyzer.jsx`. When deploying the frontend to a remote static host (such as Vercel or Netlify), this endpoint must be updated to the live URL of your deployed backend service before building production assets (`npm run build`).

## Privacy and Data Handling

ScamXRay is architected with strict data handling boundaries:

- **Message Text**: When analyzing text, the content (up to the first 3,000 characters) is transmitted to the Groq API (`openai/gpt-oss-20b`) solely to generate the plain-language explanation and safety advice. If the API key is not configured, text is processed entirely on the local backend server using deterministic rules and the ML model.
- **Link Inspection**: When inspecting URLs, the backend queries public DNS resolvers, initiates network requests to the target site to verify TLS certificates and HTTP reachability, contacts public RDAP (`rdap.org`) for domain registration age, and queries the public OpenPhish feed (`openphish.com`). All network interactions enforce strict SSRF guards that prohibit requests to private, loopback, or cloud metadata addresses.
- **Client-Side OCR**: Screenshot text extraction is performed entirely within the user's browser using Tesseract.js. Image files, pixel data, and screenshot binaries are never uploaded or transmitted to the backend server.
- **Data Storage and Server Logging**: The ScamXRay application does not use a database and does not store or log submitted message texts, URLs, or inspection results. All threat evaluation occurs in memory and is discarded immediately after returning the HTTP response. However, standard web servers (Flask/Werkzeug in development or Gunicorn in production) and hosting platforms maintain standard HTTP access logs recording connection metadata (client IP address, HTTP request method, endpoint URL `/analyze`, HTTP status code, and timestamp). Standard server access logs do not log HTTP POST request bodies, so submitted message text and URLs in POST payloads are not recorded in server access logs.
- **No User Accounts**: ScamXRay requires no registration, logins, tokens, or personal identifiers.

## Limitations

- **Advisory Guidance**: Scan results, risk scores, and threat indicators are automated assessments provided for educational and informational purposes. They do not constitute formal legal or cybersecurity guarantees.
- **No Safety Guarantee**: A verdict of "No threat found" or a "Low" risk score is not a guarantee that a communication, company, or link is safe. Attackers continuously register new domains and vary phishing tactics.
- **Model and Heuristic Accuracy**: Heuristic rules and machine learning classifiers can generate false positives or false negatives. Unconventional but legitimate job postings may trigger suspicion flags, while novel scam techniques may evade detection.
- **Feed Coverage**: OpenPhish reputation checks are limited to known threats reported to and cataloged by the OpenPhish community feed. Newly created malicious links that have not yet been cataloged will not produce a feed match.
- **Always Verify Independently**: Users should independently verify employment offers, recruitment contacts, and interview details through official corporate websites, registered telephone numbers, and authorized application portals.
