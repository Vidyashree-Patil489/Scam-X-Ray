"""
ScamXRay URL Analyzer & Verification Engine.
Separates threat risk, verification status, and network safety into distinct layers.
"""

from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlparse, parse_qs
import requests
import tldextract

# Offline TLDExtract instance using bundled Public Suffix List
_extractor = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

RESERVED_EXAMPLE_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "example", "invalid", "localhost", "test"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
    "buzz", "icu", "monster", "rest", "cam", "country", "zip", "mov"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd", "goo.gl",
    "ow.ly", "tiny.cc", "buff.ly"
}

REDIRECT_PARAM_KEYS = {
    "url", "redirect", "next", "dest", "destination", "redir", "target",
    "return", "return_url", "goto", "link", "r", "forward"
}

CREDENTIAL_PATH_WORDS = {
    "login", "signin", "password", "account", "admin", "auth", "token",
    "checkout", "payment", "bank", "kyc", "otp", "verify", "update"
}

SECURITY_WORDS = {
    "secure", "login", "verify", "update", "kyc", "support",
    "account", "official", "portal", "online", "help", "pay"
}

AMBIGUOUS_BRANDS = {"apple", "amazon", "meta", "target", "uber"}

# Brand -> official registrable domains map
# Used for impersonation / lookalike detection only (never a trust list; absent domains are not penalized)
OFFICIAL_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "irctc": {"irctc.co.in"},
    "uidai": {"uidai.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "whatsapp": {"whatsapp.com"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
    "linkedin": {"linkedin.com"},
    "naukri": {"naukri.com"},
    "indeed": {"indeed.com"},
    "internshala": {"internshala.com"},
    "apple": {"apple.com", "icloud.com"},
    "meta": {"meta.com"},
    "target": {"target.com"},
    "uber": {"uber.com"},
    "netflix": {"netflix.com"},
    "telegram": {"telegram.org", "t.me"},
}

# Backward compatibility alias
POPULAR_BRANDS = OFFICIAL_BRAND_DOMAINS

USER_CONTENT_HOSTS = {
    "github.io", "githubusercontent.com", "gitlab.io", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "herokuapp.com",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com",
    "notion.site", "linktr.ee", "carrd.co", "t.me", "wa.me",
    "chat.whatsapp.com", "discord.gg"
}

EXECUTABLE_EXTS = (
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".vbs", ".iso", ".dmg",
    ".jar", ".zip", ".rar", ".7z", ".tar.gz", ".hta", ".wsf", ".ps1"
)


def normalize_domain_label(label: str) -> str:
    """Normalise registrable domain label: lowercase, digraphs, and character leetspeak."""
    s = (label or "").lower()
    s = s.replace("rn", "m").replace("vv", "w")
    trans = str.maketrans({
        "1": "l",
        "0": "o",
        "3": "e",
        "5": "s"
    })
    return s.translate(trans)


def is_one_edit_distance(s1: str, s2: str) -> bool:
    """Return True if s1 and s2 have Levenshtein edit distance exactly 1."""
    if abs(len(s1) - len(s2)) > 1:
        return False
    if s1 == s2:
        return False
    m, n = len(s1), len(s2)
    i, j, diff = 0, 0, 0
    while i < m and j < n:
        if s1[i] != s2[j]:
            diff += 1
            if diff > 1:
                return False
            if m > n:
                i += 1
            elif n > m:
                j += 1
            else:
                i += 1
                j += 1
        else:
            i += 1
            j += 1
    if i < m or j < n:
        diff += 1
    return diff == 1


def is_user_content_platform(host: str, path: str) -> bool:
    """Return True if host/path represents a user-generated content platform."""
    h = (host or "").lower()
    p = (path or "").strip()
    if h == "github.com":
        return bool(p.strip("/"))
    for u in USER_CONTENT_HOSTS:
        if h == u or h.endswith("." + u):
            return True
    return False


def is_ip_private_or_blocked(ip_str: str) -> bool:
    """Return True if an IP is private, loopback, link-local, multicast, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or str(ip) == "169.254.169.254"
            or str(ip).startswith("0.")
        )
    except ValueError:
        return True


def check_server_connectivity(control_host: str = "iana.org", timeout: float = 1.0) -> bool:
    """Connectivity self-check: verify whether the scanning server has outbound network."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(control_host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except Exception:
        return False


def safe_resolve_dns(hostname: str, timeout: float = 2.0) -> tuple[bool, list[str], str]:
    """Resolve hostname safely. Returns (is_safe, [ips], message)."""
    if not hostname:
        return False, [], "Missing hostname"
    try:
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list({res[4][0] for res in addr_info if res[4]})
        if not ips:
            return False, [], "DNS lookup returned no records"

        for ip in ips:
            if is_ip_private_or_blocked(ip):
                return False, ips, f"Resolved to non-public/private IP: {ip}"

        return True, ips, f"Resolved to public IP: {ips[0]}"
    except socket.gaierror as e:
        return False, [], f"DNS resolution failed: {e.strerror or 'host not found'}"
    except Exception as e:
        return False, [], f"DNS lookup error: {str(e)}"


def check_tls_cert(hostname: str, port: int = 443, timeout: float = 2.5) -> tuple[bool, dict, str]:
    """Check TLS certificate validity and hostname match."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "Unknown")
                return True, {"valid": True, "notAfter": not_after}, f"Valid TLS certificate matching {hostname} (expires {not_after})"
    except ssl.SSLCertVerificationError as e:
        return False, {"valid": False}, f"TLS certificate verification failed: {e.verify_message or str(e)}"
    except Exception as e:
        return False, {"valid": False}, f"TLS handshake failed: {str(e)}"


def check_domain_age(reg_domain: str, timeout: float = 2.5) -> tuple[bool, bool, str]:
    """
    Query domain registration age via RDAP.
    Returns (check_performed, is_established, details).
    Under 30 days: 'Newly registered (N days ago)'
    30-365 days: 'Registered N months ago'
    Over a year: 'Established (registered YYYY)'
    Likely Legitimate requires age over 1 year (is_established=True).
    """
    if not reg_domain or "." not in reg_domain:
        return False, False, "Cannot query domain age for invalid domain"

    rdap_url = f"https://rdap.org/domain/{reg_domain}"
    try:
        resp = requests.get(rdap_url, timeout=timeout, headers={"Accept": "application/rdap+json", "User-Agent": "ScamXRay/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            for ev in events:
                if ev.get("eventAction") in ["registration", "created"]:
                    reg_date_str = ev.get("eventDate", "")
                    try:
                        # Normalize ISO string
                        clean_date = reg_date_str.replace("Z", "+00:00")
                        reg_dt = datetime.fromisoformat(clean_date)
                    except Exception:
                        try:
                            reg_dt = datetime.strptime(reg_date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        except Exception:
                            reg_dt = None

                    if reg_dt:
                        now_utc = datetime.now(timezone.utc)
                        days = (now_utc - reg_dt).days
                        if days < 0:
                            days = 0

                        if days < 30:
                            label = f"Newly registered ({days} day{'s' if days != 1 else ''} ago)"
                            return True, False, label
                        elif days <= 365:
                            months = max(1, days // 30)
                            label = f"Registered {months} month{'s' if months != 1 else ''} ago"
                            return True, False, label
                        else:
                            label = f"Established (registered {reg_dt.year})"
                            return True, True, label

            return True, False, f"RDAP record found for {reg_domain} (registration date unavailable)"
        return False, False, f"RDAP lookup returned HTTP {resp.status_code}"
    except Exception as e:
        return False, False, f"RDAP query failed or timed out: {str(e)}"


def check_http_reachability(url: str, timeout: float = 2.5, max_redirects: int = 3) -> tuple[bool, str]:
    """Safe HTTP reachability with strict SSRF protection across redirects."""
    current_url = url
    session = requests.Session()
    session.headers.update({"User-Agent": "ScamXRay-Verifier/1.0"})

    try:
        for _ in range(max_redirects + 1):
            parsed = urlparse(current_url)
            host = parsed.hostname or ""

            if not host:
                return False, "Malformed destination in redirect"

            # Check if host is direct IP
            try:
                ip = ipaddress.ip_address(host)
                if is_ip_private_or_blocked(str(ip)):
                    return False, f"Blocked connection to private IP: {host}"
            except ValueError:
                # DNS resolve check
                is_safe, ips, msg = safe_resolve_dns(host, timeout=1.5)
                if not is_safe:
                    return False, f"Blocked connection: {msg}"

            resp = session.get(current_url, timeout=timeout, allow_redirects=False, stream=True)
            resp.raw.read(16384)
            resp.close()

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    return True, f"HTTP {resp.status_code} redirect with no target"
                if location.startswith("/"):
                    current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                else:
                    current_url = location
            else:
                return True, f"Reachable (HTTP {resp.status_code})"

        return True, "Reachable (followed allowed redirects)"
    except Exception as e:
        return False, f"HTTP reachability check failed: {str(e)}"


def extract_threat_indicators(url: str) -> list[dict]:
    """
    Extract deterministic threat indicators:
    id, severity (critical/high/medium/low/info), points, description, value.
    """
    raw = (url or "").strip()
    to_parse = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        parsed = urlparse(to_parse)
    except ValueError:
        return [{
            "id": "malformed_url",
            "severity": "high",
            "points": 35,
            "description": "URL syntax is malformed or contains invalid control characters",
            "value": raw[:60]
        }]

    indicators = []
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()

    if not host:
        return [{
            "id": "missing_hostname",
            "severity": "medium",
            "points": 15,
            "description": "URL does not specify a valid hostname",
            "value": raw
        }]

    ext = _extractor(to_parse)
    reg_domain = ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else ""
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    tld = ext.suffix.lower() if ext.suffix else ""
    domain_label = ext.domain.lower() if ext.domain else ""

    is_ip = False
    is_private_ip = False
    try:
        ip = ipaddress.ip_address(host)
        is_ip = True
        is_private_ip = is_ip_private_or_blocked(str(ip))
    except ValueError:
        pass

    # 1. Userinfo trick (Critical: 70 pts)
    if parsed.username or "@" in (parsed.netloc or ""):
        userinfo_val = parsed.netloc.split("@", 1)[0]
        indicators.append({
            "id": "userinfo_trick",
            "severity": "critical",
            "points": 70,
            "description": "URL contains userinfo authentication syntax ('@'), often used to disguise malicious destinations",
            "value": f"{userinfo_val}@"
        })

    # 2. Lookalike detection on registered domain label (Critical / High)
    if not is_ip and reg_domain and domain_label:
        norm_label = normalize_domain_label(domain_label)
        raw_tokens = [t for t in re.split(r"[-_]+", domain_label) if t]
        norm_tokens = [t for t in re.split(r"[-_]+", norm_label) if t]
        has_security_word = any(t in SECURITY_WORDS for t in (raw_tokens + norm_tokens))

        for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
            if reg_domain in legit_domains:
                continue

            # Token matching (never substring)
            token_pairs = list(zip(raw_tokens, norm_tokens)) if len(raw_tokens) == len(norm_tokens) else [(t, normalize_domain_label(t)) for t in raw_tokens]

            brand_token_exact = any(rt == brand or nt == brand for rt, nt in token_pairs)

            # One-edit near miss or leetspeak near miss on tokens of length >= 6
            near_miss = False
            for rt, nt in token_pairs:
                if len(rt) >= 6 and len(brand) >= 6:
                    if nt == brand and rt != brand:
                        near_miss = True
                        break
                    if is_one_edit_distance(rt, brand) or is_one_edit_distance(nt, brand):
                        near_miss = True
                        break

            # Critical lookalike: brand token + security word, OR one-edit near-miss (len >= 6)
            if (brand_token_exact and has_security_word) or near_miss:
                indicators.append({
                    "id": "brand_lookalike_domain",
                    "severity": "critical",
                    "points": 70,
                    "description": f"Registered domain mimics brand '{brand}' using deception patterns ({domain_label}.{tld})",
                    "value": reg_domain
                })
                break
            # High lookalike: brand token alone for non-ambiguous brands
            elif brand_token_exact and brand not in AMBIGUOUS_BRANDS:
                indicators.append({
                    "id": "brand_lookalike_domain",
                    "severity": "high",
                    "points": 35,
                    "description": f"Registered domain incorporates brand name '{brand}' without official affiliation ({domain_label}.{tld})",
                    "value": reg_domain
                })
                break

    # 3. Subdomain brand spoof (Critical: 70 pts)
    if not is_ip and reg_domain and subdomain:
        sub_tokens = [t for t in re.split(r"[-_.]+", subdomain.lower()) if t]
        sub_norm_tokens = [t for t in re.split(r"[-_.]+", normalize_domain_label(subdomain)) if t]
        for brand, legit_domains in OFFICIAL_BRAND_DOMAINS.items():
            if (brand in sub_tokens or brand in sub_norm_tokens) and reg_domain not in legit_domains:
                indicators.append({
                    "id": "subdomain_brand_spoof",
                    "severity": "critical",
                    "points": 70,
                    "description": f"Subdomain incorporates brand '{brand}' while registered under unrelated domain '{reg_domain}'",
                    "value": host
                })
                break

    # 4. Punycode / IDN homoglyph lookalike (High: 35 pts)
    if "xn--" in host:
        indicators.append({
            "id": "homoglyph_punycode",
            "severity": "high",
            "points": 35,
            "description": "Hostname uses Internationalized Domain Name (Punycode 'xn--') syntax, frequently used for visual deception",
            "value": host
        })

    # 5. Public IP-literal host (High: 35 pts)
    if is_ip and not is_private_ip:
        indicators.append({
            "id": "ip_literal_host",
            "severity": "high",
            "points": 35,
            "description": "URL points directly to a public IP address instead of a registered domain name",
            "value": host
        })

    # 6. Executable or archive download extension (High: 35 pts)
    path_lower = path.lower()
    for ext_suffix in EXECUTABLE_EXTS:
        if path_lower.endswith(ext_suffix):
            indicators.append({
                "id": "executable_download",
                "severity": "high",
                "points": 35,
                "description": f"URL path requests direct download of an executable/archive payload ('{ext_suffix}')",
                "value": path_lower.rsplit("/", 1)[-1]
            })
            break

    # 7. External redirect parameter (Medium: 20 pts)
    # Only triggers when destination is a different registrable domain; relative URLs give no indicator
    if query:
        qs = parse_qs(query)
        for qk, qvals in qs.items():
            if qk.lower() in REDIRECT_PARAM_KEYS:
                for qv in qvals:
                    val_str = qv.strip()
                    # Same-site relative targets give no indicator
                    if val_str.startswith("/") and not val_str.startswith("//"):
                        continue
                    val_lower = val_str.lower()
                    if val_lower.startswith(("http://", "https://", "//")):
                        target_url = val_str if not val_str.startswith("//") else "http:" + val_str
                        target_host = urlparse(target_url).hostname or ""
                        target_ext = _extractor(target_host)
                        target_reg = target_ext.top_domain_under_public_suffix.lower() if target_ext.top_domain_under_public_suffix else ""
                        if target_reg and reg_domain and target_reg != reg_domain:
                            indicators.append({
                                "id": "external_redirect_param",
                                "severity": "medium",
                                "points": 20,
                                "description": f"URL query contains redirect parameter '{qk}' pointing to external domain '{target_reg}'",
                                "value": f"{qk}={qv[:60]}"
                            })
                            break

    # 8. URL shortener hiding destination (Medium: 15 pts)
    if reg_domain in SHORTENERS or host in SHORTENERS:
        indicators.append({
            "id": "url_shortener",
            "severity": "medium",
            "points": 15,
            "description": "URL uses a public link shortener that conceals the ultimate landing destination",
            "value": reg_domain or host
        })

    # 9. Unencrypted HTTP with sensitive/credential endpoint (Medium: 15 pts)
    if scheme == "http" and not is_private_ip and host not in RESERVED_EXAMPLE_DOMAINS:
        sensitive_hit = any(w in path_lower for w in CREDENTIAL_PATH_WORDS)
        if sensitive_hit:
            indicators.append({
                "id": "http_credentials",
                "severity": "medium",
                "points": 15,
                "description": "Unencrypted plain HTTP transmission used for sensitive authentication/payment endpoint",
                "value": path[:50]
            })

    # 10. Excessive subdomain depth (Medium: 15 pts)
    if subdomain:
        sub_labels = [p for p in subdomain.split(".") if p]
        if len(sub_labels) >= 3:
            indicators.append({
                "id": "excessive_subdomains",
                "severity": "medium",
                "points": 15,
                "description": f"Hostname exhibits unusual subdomain nesting depth ({len(sub_labels)} levels)",
                "value": subdomain
            })

    # 11. Heavily obfuscated length (Medium: 15 pts)
    if len(raw) > 120 and len(re.findall(r"%[0-9a-fA-F]{2}", raw)) >= 5:
        indicators.append({
            "id": "excessive_length_obfuscation",
            "severity": "medium",
            "points": 15,
            "description": "URL utilizes extensive percent-encoded obfuscation combined with long length",
            "value": f"Length {len(raw)} chars, {len(re.findall(r'%[0-9a-fA-F]{2}', raw))} encoded tokens"
        })

    # 12. Suspicious/High-abuse TLD (Low: 5 pts)
    if tld in SUSPICIOUS_TLDS:
        indicators.append({
            "id": "suspicious_tld",
            "severity": "low",
            "points": 5,
            "description": f"Domain ending '.{tld}' is associated with elevated abuse frequency across threat registries",
            "value": f".{tld}"
        })

    # 13. User-content platform (Info: 0 pts)
    if is_user_content_platform(host, path):
        indicators.append({
            "id": "user_content_platform",
            "severity": "info",
            "points": 0,
            "description": "Hosted on a user-generated content platform where domain reputation does not verify the individual page or account",
            "value": host
        })

    return indicators


def compute_threat_score(indicators: list[dict]) -> int:
    """
    Compute explainable threat score from deterministic indicators.
    Tiers:
    - critical: 70
    - high: 35
    - medium: 15-25 (explicit points: new_domain <7d=25, 7-29d=15, redirect=20; default 15)
    - low: 5
    - info: 0
    """
    if not indicators:
        return 0

    score = 0
    for ind in indicators:
        if ind.get("points") is not None:
            score += ind["points"]
        else:
            sev = ind.get("severity", "info").lower()
            if sev == "critical":
                score += 70
            elif sev == "high":
                score += 35
            elif sev == "medium":
                score += 15
            elif sev == "low":
                score += 5
            elif sev == "info":
                score += 0

    return max(0, min(100, score))


def _extract_age_days_and_est(age_perf: bool, age_ok: any, age_msg: any) -> tuple[int | None, bool]:
    """Extract age in days (if available) and is_established boolean from RDAP age check result."""
    if not age_perf:
        return None, False

    msg_str = str(age_msg or "")
    if isinstance(age_msg, (int, float)):
        days = int(age_msg)
        return days, (days > 365)

    m_days = re.search(r"Newly registered \((\d+)\s*days?\s*ago\)", msg_str, re.IGNORECASE)
    if m_days:
        return int(m_days.group(1)), False

    m_mo = re.search(r"Registered (\d+)\s*months?\s*ago", msg_str, re.IGNORECASE)
    if m_mo:
        return int(m_mo.group(1)) * 30, False

    if "established" in msg_str.lower() or "years ago" in msg_str.lower():
        return 1000, True

    is_est = bool(age_ok) and ("newly" not in msg_str.lower())
    return None, is_est


def analyze_url_comprehensive(url: str, execute_network: bool = True) -> dict:
    """
    Full URL inspection producing:
    1. Deterministic indicators list
    2. Threat score
    3. Verification checks list (DNS, TLS, Domain Age, HTTP)
    4. Deterministic verdict ('Likely Legitimate' | 'Suspicious / Potentially Fraudulent' | 'Unverified')
    5. Verdict reasoning
    """
    raw = (url or "").strip()
    to_parse = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        parsed = urlparse(to_parse)
    except ValueError:
        parsed = urlparse("http://invalid")

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    ext = _extractor(to_parse)
    reg_domain = ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else ""

    # Check for RFC 2606 reserved example domain
    is_reserved_example = (
        reg_domain in RESERVED_EXAMPLE_DOMAINS
        or host in RESERVED_EXAMPLE_DOMAINS
        or host.endswith(".example")
        or host.endswith(".test")
        or host.endswith(".invalid")
        or host.endswith(".localhost")
    )

    # Check for private/local IP
    is_private_host = False
    try:
        ip = ipaddress.ip_address(host)
        is_private_host = is_ip_private_or_blocked(str(ip))
    except ValueError:
        is_private_host = (host in ("localhost", "127.0.0.1") or host.endswith(".local") or host.endswith(".internal"))

    # 1. Evidence Layer: Indicators
    indicators = extract_threat_indicators(raw)

    # 2. Network connectivity self-check
    server_has_network = True
    if execute_network and not is_reserved_example and not is_private_host:
        server_has_network = check_server_connectivity()

    # 3. Verification Layer
    verification_checks = []
    dns_ok = False
    tls_ok = False
    age_ok = False
    http_ok = False

    # Check 1: DNS Resolution
    if is_reserved_example:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "not_performed",
            "details": f"Reserved example domain ({reg_domain or host}) under RFC 2606"
        })
    elif is_private_host:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "not_performed",
            "details": f"Private/loopback host ({host}) blocked by SSRF protection policy"
        })
    elif not host:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "failed",
            "details": "No valid hostname found in URL"
        })
    elif not execute_network:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "not_performed",
            "details": "Network checks disabled"
        })
    elif not server_has_network:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "not_performed",
            "details": "Verification unavailable: no network from the server"
        })
    else:
        # Check if host is direct public IP
        try:
            ip = ipaddress.ip_address(host)
            dns_ok = True
            verification_checks.append({
                "name": "DNS Resolution",
                "status": "performed",
                "details": f"Public IP literal: {host}"
            })
        except ValueError:
            dns_ok, ips, dns_msg = safe_resolve_dns(host)
            verification_checks.append({
                "name": "DNS Resolution",
                "status": "performed" if dns_ok else "failed",
                "details": dns_msg
            })

    # Check 2: TLS Certificate
    if scheme != "https":
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": "URL specifies unencrypted HTTP protocol"
        })
    elif is_reserved_example:
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": f"Reserved example domain ({reg_domain or host}) under RFC 2606"
        })
    elif is_private_host:
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": f"Private/loopback host ({host}) blocked by SSRF protection policy"
        })
    elif not execute_network:
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": "Network checks disabled"
        })
    elif not server_has_network:
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": "Verification unavailable: no network from the server"
        })
    elif not dns_ok:
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "not_performed",
            "details": "Skipped: host DNS did not resolve"
        })
    else:
        tls_ok, cert_data, tls_msg = check_tls_cert(host)
        verification_checks.append({
            "name": "TLS Certificate",
            "status": "performed" if tls_ok else "failed",
            "details": tls_msg
        })

    # Check 3: Domain Age (RDAP)
    if is_reserved_example:
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "not_performed",
            "details": "RFC 2606 reserved example domain has no commercial registry"
        })
    elif is_private_host or not reg_domain:
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "not_performed",
            "details": "Private IP or local host has no public domain registry"
        })
    elif not execute_network:
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "not_performed",
            "details": "Network checks disabled"
        })
    elif not server_has_network:
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "not_performed",
            "details": "Verification unavailable: no network from the server"
        })
    elif not dns_ok:
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "not_performed",
            "details": "Skipped: host DNS did not resolve"
        })
    else:
        age_perf, raw_age_ok, age_msg = check_domain_age(reg_domain)
        age_days, is_established = _extract_age_days_and_est(age_perf, raw_age_ok, age_msg)

        # Attach new_domain indicator if under 30 days
        if age_days is not None:
            if age_days < 7:
                indicators.append({
                    "id": "new_domain",
                    "severity": "medium",
                    "points": 25,
                    "description": f"Domain was registered very recently ({age_days} day{'s' if age_days != 1 else ''} ago)",
                    "value": f"{age_days} days old"
                })
            elif 7 <= age_days < 30:
                indicators.append({
                    "id": "new_domain",
                    "severity": "medium",
                    "points": 15,
                    "description": f"Domain was registered recently ({age_days} days ago)",
                    "value": f"{age_days} days old"
                })

        age_ok = is_established
        verification_checks.append({
            "name": "Domain Age (RDAP)",
            "status": "performed" if age_perf else "failed",
            "details": age_msg if isinstance(age_msg, str) else f"Domain age evaluated ({age_days or 0} days)"
        })

    # Check 4: HTTP Reachability
    if is_reserved_example:
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "not_performed",
            "details": f"Reserved example domain ({reg_domain or host}) under RFC 2606"
        })
    elif is_private_host:
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "not_performed",
            "details": f"Private/loopback host ({host}) blocked by SSRF protection policy"
        })
    elif not execute_network:
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "not_performed",
            "details": "Network checks disabled"
        })
    elif not server_has_network:
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "not_performed",
            "details": "Verification unavailable: no network from the server"
        })
    elif not dns_ok:
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "not_performed",
            "details": "Skipped: host DNS did not resolve"
        })
    else:
        http_ok, http_msg = check_http_reachability(raw)
        verification_checks.append({
            "name": "HTTP Reachability",
            "status": "performed" if http_ok else "failed",
            "details": http_msg
        })

    # Compute threat score
    threat_score = compute_threat_score(indicators)

    # 4. Deterministic Verdict Rules
    has_critical = any(i.get("severity") == "critical" for i in indicators)
    has_medium_plus = any(i.get("severity") in ["critical", "high", "medium"] for i in indicators)
    is_user_content = any(i.get("id") == "user_content_platform" for i in indicators) or is_user_content_platform(host, path)

    # Suspicious threshold: any critical indicator OR threat_score >= 35
    if has_critical or threat_score >= 35:
        verdict = "Suspicious / Potentially Fraudulent"
        top_cues = "; ".join(i["description"] for i in indicators[:2])
        verdict_reason = f"Identified {len(indicators)} structural threat indicator(s): {top_cues}."
    elif not has_medium_plus and dns_ok and tls_ok and age_ok and http_ok and not is_user_content:
        verdict = "Likely Legitimate"
        verdict_reason = f"The domain '{host}' passed positive verification: valid matching TLS, established domain age, active reachability, and zero threat indicators."
    else:
        verdict = "Unverified"
        if is_user_content:
            verdict_reason = "This is a user-content platform. The platform being legitimate does not verify this specific page or account."
        elif is_reserved_example:
            verdict_reason = f"The domain '{host}' is an RFC 2606 / RFC 6761 reserved example domain designated exclusively for documentation and testing. It is not an active commercial entity."
        elif is_private_host:
            verdict_reason = f"The host '{host}' is a private, loopback, or internal address blocked from fetching by SSRF protection policy."
        elif not server_has_network and execute_network:
            verdict_reason = "No threat indicators detected in URL syntax. Positive verification is unavailable because the scanning server has no outbound network connection."
        else:
            caution_count = len(indicators)
            failed_checks = [c["name"] for c in verification_checks if c["status"] == "failed"]
            if caution_count > 0:
                top_ind = indicators[0]["description"]
                verdict_reason = f"Identified {caution_count} caution indicator(s): {top_ind}. Domain remains unverified."
            elif failed_checks:
                verdict_reason = f"No threat indicators detected, but verification could not be completed ({', '.join(failed_checks)} failed or timed out)."
            else:
                verdict_reason = "No threat indicators detected in URL syntax, but positive verification evidence is incomplete."

    return {
        "url": raw,
        "hostname": host,
        "registered_domain": reg_domain,
        "scheme": scheme,
        "is_reserved_example": is_reserved_example,
        "threat_score": threat_score,
        "url_score": threat_score,
        "indicators": indicators,
        "url_flags": [f"{i['id']}: {i['description']} ('{i['value']}')" for i in indicators],
        "verification_checks": verification_checks,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
    }


def analyze_url(url: str, execute_network: bool = True) -> dict:
    """Backward-compatible entry point for existing imports."""
    return analyze_url_comprehensive(url, execute_network=execute_network)
