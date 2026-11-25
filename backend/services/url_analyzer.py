"""
ScamXRay URL Analyzer & Verification Engine.
Separates threat risk, verification status, and network safety into distinct layers.
"""

import concurrent.futures
from datetime import datetime, timezone
import ipaddress
import os
import re
import socket
import ssl
import time
from urllib.parse import urlparse, parse_qs, urljoin
import requests
import tldextract

try:
    from services.reputation import check_openphish
except ImportError:
    from reputation import check_openphish

# Offline TLDExtract instance using bundled Public Suffix List
_extractor = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

RESERVED_EXAMPLE_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "example", "invalid", "test"
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


def get_explicit_scheme(u: str) -> str | None:
    """Extract explicit scheme if present, distinguishing schemes from host:port patterns."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)", (u or "").strip())
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = m.group(2)
    # If scheme:rest is actually host:port (rest starts with digits and either ends or has /)
    if re.match(r"^\d+(?:/|$)", rest):
        return None
    return scheme


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    Detect and parse IP literals in all forms:
    dotted decimal, decimal integer (2130706433), hex (0x7f000001), octal,
    short-form classful (127.1), IPv6 ([::1]), and IPv4-mapped IPv6 (::ffff:127.0.0.1).
    """
    if not host:
        return None
    h = host.strip().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]

    # 1. Standard ipaddress parser (dotted decimal, IPv6, IPv4-mapped IPv6)
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass

    # 2. C-style numeric representations (decimal, hex, octal, short forms) via socket.inet_aton
    try:
        raw_bytes = socket.inet_aton(h)
        if len(raw_bytes) == 4:
            return ipaddress.IPv4Address(raw_bytes)
    except (OSError, ValueError):
        pass

    return None


def is_ip_non_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IP is private, loopback, link-local, multicast, reserved, unspecified, or cloud metadata."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        if is_ip_non_public(ip.ipv4_mapped):
            return True

    ip_str = str(ip)
    # Cloud metadata special addresses
    if ip_str in ("169.254.169.254", "fd00:ec2::254"):
        return True
    # 0.0.0.0/8 current network
    if isinstance(ip, ipaddress.IPv4Address) and (ip_str.startswith("0.") or ip_str == "0.0.0.0"):
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def is_internal_hostname(host: str) -> bool:
    """Return True if host is localhost, *.localhost, *.local, or *.internal."""
    h = (host or "").lower().rstrip(".")
    if h in ("localhost", "local", "internal"):
        return True
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return False


def normalize_url(url: str) -> dict:
    """
    Normalise URL:
    - Accept input without https:// (default to https:// if scheme omitted, preserving http:// if provided)
    - Strip trailing dot from hostnames ("example.com." -> "example.com") BEFORE any IP detection
    - Lowercase host
    - Decode punycode (IDNA)
    - Extract registrable domain using tldextract
    """
    raw = (url or "").strip()
    if not raw:
        return {
            "raw": "",
            "normalized_url": "",
            "scheme": "",
            "host": "",
            "decoded_host": "",
            "path": "",
            "query": "",
            "reg_domain": "",
            "subdomain": "",
            "tld": "",
            "domain_label": "",
            "unsupported_scheme": None,
        }

    explicit_scheme = get_explicit_scheme(raw)
    unsupported_scheme = None
    if explicit_scheme is not None and explicit_scheme not in ("http", "https"):
        unsupported_scheme = explicit_scheme
        to_parse = raw
    elif explicit_scheme is None:
        to_parse = "https://" + raw
    else:
        to_parse = raw

    try:
        parsed = urlparse(to_parse)
    except Exception:
        parsed = urlparse("https://invalid")

    scheme = (parsed.scheme or "https").lower()
    # Strip trailing dot from hostname BEFORE IP detection
    raw_host = (parsed.hostname or "").lower().rstrip(".")

    # Decode punycode
    decoded_host = raw_host
    if "xn--" in raw_host:
        try:
            decoded_host = raw_host.encode("ascii").decode("idna").lower()
        except Exception:
            decoded_host = raw_host

    path = parsed.path or "/"
    query = parsed.query or ""
    port = parsed.port

    port_suffix = f":{port}" if port and not (scheme == "https" and port == 443) and not (scheme == "http" and port == 80) else ""
    norm_url = f"{scheme}://{raw_host}{port_suffix}{path}"
    if query:
        norm_url += f"?{query}"

    ext = _extractor(raw_host)
    reg_domain = ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else ""
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    tld = ext.suffix.lower() if ext.suffix else ""
    domain_label = ext.domain.lower() if ext.domain else ""

    return {
        "raw": raw,
        "normalized_url": norm_url,
        "scheme": scheme,
        "host": raw_host,
        "decoded_host": decoded_host,
        "path": path,
        "query": query,
        "parsed": parsed,
        "netloc": parsed.netloc,
        "username": parsed.username,
        "reg_domain": reg_domain,
        "subdomain": subdomain,
        "tld": tld,
        "domain_label": domain_label,
        "unsupported_scheme": unsupported_scheme,
    }


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
    parsed = parse_ip_literal(ip_str)
    if not parsed:
        return False
    return is_ip_non_public(parsed)


def check_server_connectivity(control_host: str = "iana.org", timeout: float = 1.0) -> bool:
    """Connectivity self-check: verify whether the scanning server has outbound network."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(control_host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except Exception:
        return False


def safe_resolve_dns(hostname: str, timeout: float = 2.0) -> tuple[bool, list[str], str]:
    """Resolve hostname safely. Checks ALL resolved IPs. Returns (is_safe, [ips], message)."""
    h = (hostname or "").lower().rstrip(".")
    if not h:
        return False, [], "Missing hostname"

    # Static check for private IP literal or internal hostname
    parsed_ip = parse_ip_literal(h)
    if parsed_ip and is_ip_non_public(parsed_ip):
        return False, [str(parsed_ip)], f"Blocked: private or internal address ({parsed_ip})"
    if is_internal_hostname(h):
        return False, [], f"Blocked: private or internal address ({h})"

    try:
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(h, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list({res[4][0] for res in addr_info if res[4]})
        if not ips:
            return False, [], "Could not resolve domain"

        for ip in ips:
            if is_ip_private_or_blocked(ip):
                return False, ips, f"Blocked: resolved to private or internal address ({ip})"

        return True, ips, f"Resolved to public IP: {ips[0]}"
    except socket.gaierror:
        return False, [], "Could not resolve domain"
    except socket.timeout:
        return False, [], "DNS resolution timed out"
    except Exception:
        return False, [], "Could not resolve domain"


def check_tls_cert(hostname: str, port: int = 443, timeout: float = 2.5) -> tuple[bool, dict, str]:
    """Check TLS certificate validity and hostname match, verifying connected peer IP."""
    h = (hostname or "").lower().rstrip(".")
    # If host is private or internal, do not connect
    parsed_ip = parse_ip_literal(h)
    if (parsed_ip and is_ip_non_public(parsed_ip)) or is_internal_hostname(h):
        return False, {"valid": False}, "Blocked: private or internal address; ScamXRay does not connect to it"

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((h, port), timeout=timeout) as sock:
            peer_ip = sock.getpeername()[0]
            if is_ip_private_or_blocked(peer_ip):
                return False, {"valid": False}, "Blocked: private or internal address; ScamXRay does not connect to it"
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "Unknown")
                return True, {"valid": True, "notAfter": not_after}, f"Valid TLS certificate matching {h} (expires {not_after})"
    except ssl.SSLCertVerificationError:
        return False, {"valid": False}, f"TLS certificate verification failed for {h}"
    except (socket.timeout, TimeoutError):
        return False, {"valid": False}, "TLS connection timed out"
    except ConnectionRefusedError:
        return False, {"valid": False}, "Connection refused"
    except Exception:
        return False, {"valid": False}, "TLS handshake failed"


def check_domain_age(reg_domain: str, timeout: float = 5.0, max_retries: int = 1) -> tuple[bool, bool, str]:
    """
    Query domain registration age via RDAP.
    Returns (check_performed, is_established, details).
    Under 30 days: 'Newly registered (N days ago)'
    30-365 days: 'Registered N months ago'
    Over a year: 'Established (registered YYYY)'
    Likely Legitimate requires age over 1 year (is_established=True).
    Retries once on timeout or connection error.
    """
    if not reg_domain or "." not in reg_domain:
        return False, False, "Cannot query domain age for invalid domain"

    rdap_url = f"https://rdap.org/domain/{reg_domain}"
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(
                rdap_url,
                timeout=timeout,
                headers={"Accept": "application/rdap+json", "User-Agent": "ScamXRay/1.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                for ev in events:
                    if ev.get("eventAction") in ["registration", "created"]:
                        reg_date_str = ev.get("eventDate", "")
                        try:
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
            elif resp.status_code == 404:
                return False, False, "Domain registration record not found in RDAP"
            elif attempt < max_retries and resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(0.3)
                continue
            last_err = f"RDAP lookup returned HTTP {resp.status_code}"
        except requests.Timeout:
            last_err = "Domain age lookup timed out"
            if attempt < max_retries:
                time.sleep(0.3)
                continue
        except requests.ConnectionError:
            last_err = "Could not connect to RDAP service"
            if attempt < max_retries:
                time.sleep(0.3)
                continue
        except Exception:
            last_err = "Domain age query failed"

    return False, False, last_err or "Domain age check failed"


def check_http_reachability(url: str, timeout: float = 5.0, max_redirects: int = 3, max_retries: int = 1) -> tuple[bool, str]:
    """Safe HTTP reachability with strict SSRF protection across redirects."""
    raw_target = (url or "").strip()
    if not raw_target:
        return False, "Missing URL for reachability check"

    # Ensure default scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_target):
        current_url = "https://" + raw_target
    else:
        current_url = raw_target

    session = requests.Session()
    session.headers.update({"User-Agent": "ScamXRay-Verifier/1.0"})

    try:
        for hop in range(max_redirects + 1):
            parsed = urlparse(current_url)
            scheme = (parsed.scheme or "https").lower()
            if scheme not in ("http", "https"):
                return False, f"Blocked unsupported scheme in redirect: {scheme}"

            host = (parsed.hostname or "").lower().rstrip(".")
            if not host:
                return False, "Malformed destination in redirect"

            # Strict SSRF check on every hop
            parsed_ip = parse_ip_literal(host)
            if (parsed_ip and is_ip_non_public(parsed_ip)) or is_internal_hostname(host):
                return False, "Blocked: private or internal address; ScamXRay does not connect to it"

            is_safe, ips, msg = safe_resolve_dns(host, timeout=2.0)
            if not is_safe:
                return False, msg

            port_suffix = f":{parsed.port}" if parsed.port and not (scheme == "https" and parsed.port == 443) and not (scheme == "http" and parsed.port == 80) else ""
            current_url = f"{scheme}://{host}{port_suffix}{parsed.path or '/'}"
            if parsed.query:
                current_url += f"?{parsed.query}"

            resp = None
            last_err = None
            for attempt in range(max_retries + 1):
                try:
                    resp = session.get(current_url, timeout=timeout, allow_redirects=False, stream=True)
                    # Verify peer socket IP if available
                    try:
                        sock = getattr(getattr(resp, "raw", None), "_connection", None)
                        if sock and hasattr(sock, "sock") and sock.sock:
                            peer_ip = sock.sock.getpeername()[0]
                            if is_ip_private_or_blocked(peer_ip):
                                resp.close()
                                return False, "Blocked: private or internal address; ScamXRay does not connect to it"
                    except Exception:
                        pass
                    resp.raw.read(16384)
                    resp.close()
                    break
                except requests.Timeout:
                    last_err = "Connection timed out"
                    if attempt < max_retries:
                        time.sleep(0.3)
                        continue
                except requests.ConnectionError:
                    last_err = "Could not connect to server"
                    if attempt < max_retries:
                        time.sleep(0.3)
                        continue
                except Exception:
                    return False, "HTTP reachability check failed"

            if resp is None:
                return False, last_err or "Connection timed out"

            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    return True, f"HTTP {resp.status_code} redirect with no target"

                # Safely resolve relative, protocol-relative (//), or absolute redirect targets
                next_url = urljoin(current_url, location.strip())
                parsed_next = urlparse(next_url)
                next_scheme = (parsed_next.scheme or "").lower()
                next_host = (parsed_next.hostname or "").lower().rstrip(".")

                if not next_host or next_scheme not in ("http", "https"):
                    return False, f"Malformed destination in redirect: {location}"

                port_suffix = f":{parsed_next.port}" if parsed_next.port and not (next_scheme == "https" and parsed_next.port == 443) and not (next_scheme == "http" and parsed_next.port == 80) else ""
                current_url = f"{next_scheme}://{next_host}{port_suffix}{parsed_next.path or '/'}"
                if parsed_next.query:
                    current_url += f"?{parsed_next.query}"
            else:
                return True, f"Reachable (HTTP {resp.status_code})"

        return True, "Reachable (followed allowed redirects)"
    except Exception:
        return False, "HTTP reachability check failed"


def extract_threat_indicators(url: str) -> list[dict]:
    """
    Extract deterministic threat indicators:
    id, severity (critical/high/medium/low/info), points, description, value.
    """
    comp = normalize_url(url)
    raw = comp["raw"]
    if not raw:
        return []

    host = comp["host"]
    decoded_host = comp["decoded_host"]
    path = comp["path"]
    query = comp["query"]
    scheme = comp["scheme"]
    reg_domain = comp["reg_domain"]
    subdomain = comp["subdomain"]
    tld = comp["tld"]
    domain_label = comp["domain_label"]

    if not host:
        return [{
            "id": "missing_hostname",
            "severity": "medium",
            "points": 15,
            "description": "URL does not specify a valid hostname",
            "value": raw
        }]

    indicators = []

    is_ip = False
    is_private_ip = False
    parsed_ip = parse_ip_literal(host)
    if parsed_ip:
        is_ip = True
        is_private_ip = is_ip_non_public(parsed_ip)

    # 1. Userinfo trick (Critical: 70 pts)
    netloc_str = comp.get("netloc") or ""
    username_str = comp.get("username") or ""
    if username_str or "@" in netloc_str:
        userinfo_val = netloc_str.split("@", 1)[0]
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
    if "xn--" in host or "xn--" in decoded_host:
        indicators.append({
            "id": "homoglyph_punycode",
            "severity": "high",
            "points": 35,
            "description": "Hostname uses Internationalized Domain Name (Punycode 'xn--') syntax, frequently used for visual deception",
            "value": f"{host} (decoded: {decoded_host})" if decoded_host != host else host
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

    # 12. Uncommon TLD (Info: 0 pts)
    if tld in SUSPICIOUS_TLDS:
        indicators.append({
            "id": "suspicious_tld",
            "severity": "info",
            "points": 0,
            "description": "Uncommon top-level domain; not a threat signal on its own.",
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
    comp = normalize_url(url)
    raw = comp["raw"]
    norm_url = comp["normalized_url"]
    scheme = comp["scheme"]
    host = comp["host"]
    decoded_host = comp["decoded_host"]
    path = comp["path"]
    reg_domain = comp["reg_domain"]

    # Reject unsupported schemes cleanly
    if comp.get("unsupported_scheme"):
        return {
            "error": "Only http and https links are supported",
            "url": raw,
            "raw_url": raw,
            "hostname": host,
            "registered_domain": reg_domain,
            "scheme": comp.get("unsupported_scheme"),
            "is_reserved_example": False,
            "threat_score": 0,
            "url_score": 0,
            "indicators": [],
            "url_flags": [],
            "verification": [],
            "verification_checks": [],
            "evidence": [],
            "limitations": [
                "Only http and https links are supported"
            ],
            "recommended_actions": [
                "Provide a standard web link starting with http:// or https://."
            ],
            "verdict": "Unknown",
            "url_verdict": "Unknown",
            "verdict_reason": "Only http and https links are supported",
            "url_verdict_reason": "Only http and https links are supported",
            "confidence": "low",
        }

    # Input validation: reject whitespace or multiple URLs
    base_part = raw.split("?", 1)[0].split("#", 1)[0]
    has_multiple = (
        len(re.findall(r"https?://", base_part, re.IGNORECASE)) > 1
        or ("," in base_part and len([p for p in base_part.split(",") if "." in p.strip()]) > 1)
        or (";" in base_part and len([p for p in base_part.split(";") if "." in p.strip()]) > 1)
    )
    if re.search(r"\s", raw) or has_multiple:
        return {
            "error": "Enter one URL at a time",
            "url": raw,
            "raw_url": raw,
            "hostname": "",
            "registered_domain": "",
            "scheme": "",
            "is_reserved_example": False,
            "threat_score": 0,
            "url_score": 0,
            "indicators": [],
            "url_flags": [],
            "verification": [],
            "verification_checks": [],
            "evidence": [],
            "limitations": [
                "No match in a feed does not mean the link is safe"
            ],
            "recommended_actions": [
                "Enter one valid URL at a time without spaces."
            ],
            "verdict": "Unknown",
            "url_verdict": "Unknown",
            "verdict_reason": "Enter one URL at a time",
            "url_verdict_reason": "Enter one URL at a time",
            "confidence": "low",
        }

    # Check for RFC 2606 reserved example domain
    is_reserved_example = (
        reg_domain in RESERVED_EXAMPLE_DOMAINS
        or host in RESERVED_EXAMPLE_DOMAINS
        or host.endswith(".example")
        or host.endswith(".test")
        or host.endswith(".invalid")
    )

    # Check for static private/internal host
    parsed_ip = parse_ip_literal(host)
    is_ip = parsed_ip is not None
    is_static_private = (is_ip and is_ip_non_public(parsed_ip)) or is_internal_hostname(host)

    # DNS pre-check for hostname to catch DNS rebinding before reputation or network checks
    is_dns_private = False
    dns_resolved_ips = []
    dns_msg = ""
    dns_ok = False

    if not is_static_private and not is_reserved_example and host and not is_ip:
        if execute_network:
            dns_ok, dns_resolved_ips, dns_msg = safe_resolve_dns(host)
            if any(is_ip_private_or_blocked(ip) for ip in dns_resolved_ips) or "private or internal" in dns_msg.lower():
                is_dns_private = True
        else:
            dns_ok = False
            dns_msg = "Network checks disabled"

    is_private_host = is_static_private or is_dns_private

    # 1. Evidence Layer: Indicators
    indicators = extract_threat_indicators(raw)

    # 2. Network connectivity self-check
    server_has_network = True
    if execute_network and not is_reserved_example and not is_private_host:
        server_has_network = check_server_connectivity()

    # 3. Verification Layer & Concurrent Reputation Lookups
    verification_checks = []
    tls_ok = False
    age_ok = False
    http_ok = False
    openphish_result = None

    if is_private_host:
        blocked_msg = "Blocked: private or internal address; ScamXRay does not connect to it"
        openphish_result = {
            "source": "OpenPhish",
            "status": "not_checked",
            "detail": blocked_msg,
            "failed": False
        }
        verification_checks = [
            {"name": "DNS Resolution", "status": "not_performed", "details": blocked_msg},
            {"name": "TLS Certificate", "status": "not_performed", "details": blocked_msg},
            {"name": "Domain Age (RDAP)", "status": "not_performed", "details": blocked_msg},
            {"name": "HTTP Reachability", "status": "not_performed", "details": blocked_msg},
        ]
        dns_ok = False
    elif is_reserved_example:
        res_msg = f"Reserved example domain ({reg_domain or host}) under RFC 2606"
        verification_checks = [
            {"name": "DNS Resolution", "status": "not_performed", "details": res_msg},
            {"name": "TLS Certificate", "status": "not_performed", "details": res_msg},
            {"name": "Domain Age (RDAP)", "status": "not_performed", "details": res_msg},
            {"name": "HTTP Reachability", "status": "not_performed", "details": res_msg},
        ]
        dns_ok = False
        openphish_result = check_openphish(norm_url)
    elif not host:
        verification_checks.append({
            "name": "DNS Resolution",
            "status": "failed",
            "details": "No valid hostname found in URL"
        })
        verification_checks.append({"name": "TLS Certificate", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})
        verification_checks.append({"name": "Domain Age (RDAP)", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})
        verification_checks.append({"name": "HTTP Reachability", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})
        openphish_result = check_openphish(norm_url)
    elif not execute_network:
        verification_checks = [
            {"name": "DNS Resolution", "status": "not_performed", "details": "Network checks disabled"},
            {"name": "TLS Certificate", "status": "not_performed", "details": "Network checks disabled"},
            {"name": "Domain Age (RDAP)", "status": "not_performed", "details": "Network checks disabled"},
            {"name": "HTTP Reachability", "status": "not_performed", "details": "Network checks disabled"},
        ]
        openphish_result = check_openphish(norm_url)
    elif not server_has_network:
        verification_checks = [
            {"name": "DNS Resolution", "status": "not_performed", "details": "Verification unavailable: no network from the server"},
            {"name": "TLS Certificate", "status": "not_performed", "details": "Verification unavailable: no network from the server"},
            {"name": "Domain Age (RDAP)", "status": "not_performed", "details": "Verification unavailable: no network from the server"},
            {"name": "HTTP Reachability", "status": "not_performed", "details": "Verification unavailable: no network from the server"},
        ]
        openphish_result = check_openphish(norm_url)
    else:
        # Check 1: DNS Resolution
        if parsed_ip:
            dns_ok = True
            verification_checks.append({
                "name": "DNS Resolution",
                "status": "performed",
                "details": f"Public IP literal: {host}"
            })
        else:
            verification_checks.append({
                "name": "DNS Resolution",
                "status": "performed" if dns_ok else "failed",
                "details": dns_msg
            })

        # Concurrent execution of Reputation (OpenPhish) and Infrastructure (TLS, RDAP, HTTP)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            fut_op = executor.submit(check_openphish, norm_url)
            fut_tls = executor.submit(check_tls_cert, host) if (dns_ok and scheme == "https") else None
            fut_age = executor.submit(check_domain_age, reg_domain) if (dns_ok and reg_domain) else None
            fut_http = executor.submit(check_http_reachability, norm_url) if dns_ok else None

            # Retrieve reputation results
            openphish_result = fut_op.result()

            if dns_ok:
                # Check 2: TLS Certificate
                if fut_tls:
                    tls_ok, cert_data, tls_msg = fut_tls.result()
                    verification_checks.append({
                        "name": "TLS Certificate",
                        "status": "performed" if tls_ok else "failed",
                        "details": tls_msg
                    })
                else:
                    tls_ok = False
                    verification_checks.append({
                        "name": "TLS Certificate",
                        "status": "not_performed",
                        "details": "URL specifies unencrypted HTTP protocol"
                    })

                # Check 3: Domain Age (RDAP)
                if fut_age:
                    age_perf, raw_age_ok, age_msg = fut_age.result()
                    age_days, is_established = _extract_age_days_and_est(age_perf, raw_age_ok, age_msg)

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
                else:
                    verification_checks.append({
                        "name": "Domain Age (RDAP)",
                        "status": "not_performed",
                        "details": "Private IP or local host has no public domain registry"
                    })

                # Check 4: HTTP Reachability
                http_ok, http_msg = fut_http.result()
                verification_checks.append({
                    "name": "HTTP Reachability",
                    "status": "performed" if http_ok else "failed",
                    "details": http_msg
                })
            else:
                verification_checks.append({"name": "TLS Certificate", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})
                verification_checks.append({"name": "Domain Age (RDAP)", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})
                verification_checks.append({"name": "HTTP Reachability", "status": "not_performed", "details": "Skipped: host DNS did not resolve"})

    if openphish_result and openphish_result.get("status") == "match":
        indicators.insert(0, {
            "id": "openphish_reputation_match",
            "severity": "critical",
            "points": 100,
            "description": "URL matched active phishing threat intelligence entry in OpenPhish community feed",
            "value": openphish_result.get("detail", host)
        })

    # Compute threat score
    threat_score = compute_threat_score(indicators)

    for c in verification_checks:
        c["check"] = c.get("name", "")

    # 4. Deterministic Verdict Rules (4-Verdict Model: Malicious, Suspicious, No threat found, Unknown)
    is_user_content = any(i.get("id") == "user_content_platform" for i in indicators) or is_user_content_platform(host, path)
    has_critical = any(i.get("severity") == "critical" for i in indicators)
    has_high = any(i.get("severity") == "high" for i in indicators)
    non_critical_indicators = [i for i in indicators if i.get("severity") in ("medium", "low")]
    has_several_non_critical = (len(non_critical_indicators) >= 2 and threat_score >= 30)

    # Verdict 1: Malicious (Reputation feed match: OpenPhish)
    has_feed_match = (openphish_result.get("status") == "match")
    if has_feed_match:
        verdict = "Malicious"
        threat_score = 100
        confidence = "high"
        verdict_reason = "Active threat intelligence match: identified as malicious threat in OpenPhish community feed."

    # Verdict 2: Suspicious (Critical indicator, high indicator, or several non-critical indicators together)
    elif has_critical or has_high or has_several_non_critical:
        verdict = "Suspicious"
        threat_score = max(threat_score, 35) if (has_critical or has_high) else threat_score
        confidence = "high" if (has_critical or has_high) else "medium"
        top_cues = "; ".join(i["description"] for i in indicators[:2])
        verdict_reason = f"Identified {len(indicators)} structural threat indicator(s): {top_cues}."

    # Verdict 3: Clean infrastructure checks passed, zero threat indicators, zero feed match
    # NEVER use words 'safe', 'verified', or 'clean' in reasoning or verdicts
    elif dns_ok and tls_ok and age_ok and http_ok and len([i for i in indicators if i.get("severity") != "info"]) == 0 and not is_user_content and not is_reserved_example and not is_private_host:
        openphish_failed = (
            openphish_result.get("failed") is True
            or (execute_network and openphish_result.get("status") == "not_checked")
        )

        if openphish_failed:
            verdict = "Unknown"
            threat_score = 0
            confidence = "low"
            verdict_reason = "A reputation check could not be completed (OpenPhish feed unavailable)"
        else:
            verdict = "No threat found"
            threat_score = 0
            confidence = "high"
            verdict_reason = f"The domain '{host}' completed infrastructure evaluations: valid matching TLS certificate, established domain age, active HTTP reachability, and zero threat indicators identified."

    # Verdict 4: Unknown (Checks failed, could not run, user-content platform, or isolated caution indicator)
    # Failed verification checks must never raise threat level
    else:
        verdict = "Unknown"
        confidence = "medium" if (is_user_content or is_reserved_example) else "low"
        non_info_indicators = [i for i in indicators if i.get("severity") != "info"]
        if not non_info_indicators:
            threat_score = 0

        if is_user_content:
            verdict_reason = f"This link is hosted on a user-content platform ('{host}'). Platform reputation does not verify or attest to the legitimacy of individual pages or accounts."
        elif is_reserved_example:
            verdict_reason = f"The domain '{host}' is an RFC 2606 / RFC 6761 reserved example domain designated exclusively for documentation and testing. It is not an active commercial entity."
        elif is_private_host:
            verdict_reason = f"The host '{host}' is a private or internal address; ScamXRay does not connect to it."
        elif not server_has_network and execute_network:
            verdict_reason = "Zero threat indicators detected in URL syntax. Infrastructure evaluations are unavailable because the scanning server has no outbound network connection."
        elif len(non_info_indicators) > 0:
            top_ind = non_info_indicators[0]["description"]
            verdict_reason = f"Identified {len(non_info_indicators)} caution indicator(s): {top_ind}. Domain identity remains unconfirmed."
        else:
            failed_checks = [c["name"] for c in verification_checks if c["status"] == "failed"]
            if failed_checks:
                verdict_reason = f"Zero threat indicators detected, but technical checks could not be completed ({', '.join(failed_checks)} failed or timed out). Incomplete evaluations do not imply malicious intent."
            else:
                verdict_reason = "Zero threat indicators detected in URL syntax, but positive evaluation evidence is incomplete."

    # Evidence, Limitations & Recommended Actions
    evidence = [
        {
            "source": "OpenPhish Community Feed",
            "status": openphish_result.get("status", "not_checked"),
            "result": openphish_result.get("detail", "Feed lookup completed")
        },
        {
            "source": "Structural Threat Indicators",
            "result": (
                f"Identified {len(indicators)} indicator(s): " + "; ".join(i["description"] for i in indicators[:3])
                if indicators else "Zero heuristic or structural threat indicators detected"
            )
        },
        {
            "source": "Infrastructure Evaluations",
            "result": (
                "; ".join(f"{c['name']}: {c['status']} ({c['details']})" for c in verification_checks if c.get("status") in ("performed", "failed"))
                or "No network checks performed"
            )
        }
    ]

    limitations = [
        "No match in a feed does not mean the link is safe",
        "Threat intelligence feeds capture known and reported phishing links; newly launched campaigns may not appear immediately.",
        "Infrastructure checks evaluate technical protocol and domain setup, not page content or author intent.",
    ]
    if is_user_content:
        limitations.append("Platform-level presence does not attest to the safety or legitimacy of user-submitted content.")

    if verdict == "Malicious":
        recommended_actions = [
            "Do not open this link or submit any passwords, credentials, or personal information.",
            "If received via an unsolicited message, email, or job offer, report and block the sender.",
            "If you already visited the link, immediately reset passwords on affected accounts and scan your device.",
        ]
    elif verdict == "Suspicious":
        recommended_actions = [
            "Exercise extreme caution; do not enter sensitive credentials, financial data, or identification documents.",
            "Independently navigate to the official organization website using a trusted search engine instead of clicking the link.",
            "Carefully examine the domain name in your browser address bar for spelling discrepancies or deceptive suffixes.",
        ]
    elif verdict == "No threat found":
        recommended_actions = [
            "Always inspect the browser address bar to ensure you are on the intended website before submitting confidential data.",
            "Never share passwords, one-time codes, or personal identification in response to unsolicited requests.",
        ]
    else:  # Unknown
        recommended_actions = [
            "Treat this link with caution as its identity and infrastructure could not be fully evaluated.",
            "If hosted on a shared document, form, or repository platform, independently confirm the author's identity.",
            "Avoid downloading unknown files or providing credentials on unconfirmed platforms.",
        ]

    return {
        "url": norm_url,
        "raw_url": raw,
        "hostname": host,
        "registered_domain": reg_domain,
        "scheme": scheme,
        "is_reserved_example": is_reserved_example,
        "threat_score": threat_score,
        "url_score": threat_score,
        "indicators": indicators,
        "url_flags": [f"{i['id']}: {i['description']} ('{i['value']}')" for i in indicators],
        "verification": verification_checks,
        "verification_checks": verification_checks,
        "evidence": evidence,
        "limitations": limitations,
        "recommended_actions": recommended_actions,
        "verdict": verdict,
        "url_verdict": verdict,
        "verdict_reason": verdict_reason,
        "url_verdict_reason": verdict_reason,
        "confidence": confidence,
    }


def analyze_url(url: str, execute_network: bool = True) -> dict:
    """Backward-compatible entry point for existing imports."""
    return analyze_url_comprehensive(url, execute_network=execute_network)
