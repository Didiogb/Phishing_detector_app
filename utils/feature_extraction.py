import tldextract
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    # Authentication & Access
    'login', 'signin', 'signup', 'register', 'authenticate', 'verify', 'verification', 'reset', 'password', 'passcode',
    # Security & Alerts
    'secure', 'security', 'update', 'alert', 'warning', 'suspend', 'suspended', 'blocked', 'unauthorized', 'expired',
    # Banking & Payments
    'bank', 'paypal', 'billing', 'invoice', 'transaction', 'payment', 'credit', 'debit', 'refund', 'cash', 'loan',
    # Brand Imitation
    'apple', 'amazon', 'google', 'facebook', 'microsoft', 'outlook', 'office365', 'yahoo', 'instagram', 'tiktok',
    # Admin & Control
    'admin', 'cpanel', 'manage', 'portal', 'dashboard', 'support', 'service', 'customer', 'helpdesk',
    # Miscellaneous phishing indicators
    'confirm', 'account', 'updateinfo', 'recovery', 'validation', 'unlock', 'activate', 'restore', 'access', 'authorize'
]


def extract_features(url):
    """Extracts structured numerical features from a full URL."""
    def count_digits(s): return sum(c.isdigit() for c in s)
    def count_chars(s, ch): return s.count(ch)
    def count_suspicious_tokens(s): return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in s.lower())

    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    domain = parsed.netloc or parsed.path
    ext = tldextract.extract(domain)

    subdomain = ext.subdomain or ""
    d = ext.domain or ""

    return {
        "url_len": len(url),
        "num_digits": count_digits(url),
        "num_hyphens": count_chars(url, "-"),
        "num_dots": url.count("."),
        "suspicious_words": count_suspicious_tokens(url),
        "subdomain_count": 0 if subdomain == "" else len(subdomain.split(".")),
        "domain_len": len(d),
        "uses_https": 1 if url.lower().startswith("https://") else 0,
        "uses_http": 1 if url.lower().startswith("http://") else 0
    }
