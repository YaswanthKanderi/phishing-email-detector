"""
Security Feature Extractor
---------------------------
Extracts phishing-specific signals beyond basic NLP — the kind of heuristics
used by real email security gateways (Proofpoint, Mimecast, Microsoft Defender).

These hand-crafted features dramatically improve detection on novel phishing
attempts where TF-IDF alone may miss the signal.
"""

import re
from urllib.parse import urlparse


# Known suspicious TLDs commonly abused by phishing campaigns
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',          # Free TLDs heavily abused
    'xyz', 'top', 'click', 'download',      # Cheap/low-reputation
    'zip', 'mov', 'country',                # Recently added, under scrutiny
}

# Urgency / social-engineering keywords (case-insensitive)
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'verify now', 'suspended', 'suspend',
    'locked', 'expire', 'expires', 'act now', 'within 24 hours',
    'final notice', 'last warning', 'unusual activity', 'unauthorized',
    'confirm your', 'update your', 'click here', 'limited time',
    'action required', 'warning:', 'alert:', 'attention:',
]

# Financial / credential lure keywords
FINANCIAL_LURES = [
    'bank account', 'credit card', 'password', 'ssn', 'social security',
    'wire transfer', 'refund', 'invoice', 'payment', 'tax refund',
    'gift card', 'bitcoin', 'cryptocurrency', 'paypal', 'western union',
]

# Brand impersonation keywords (common phishing targets)
IMPERSONATED_BRANDS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix',
    'facebook', 'instagram', 'linkedin', 'dhl', 'fedex', 'ups',
    'ato', 'ird', 'irs', 'hmrc', 'mygov', 'medicare',
]

# Generic greetings (phishing hallmark — legitimate senders use your name)
GENERIC_GREETINGS = [
    'dear customer', 'dear user', 'dear member', 'dear client',
    'dear account holder', 'dear valued customer', 'hello user',
    'hi customer', 'dear sir/madam', 'to whom it may concern',
]


class SecurityFeatureExtractor:
    """Extracts hand-crafted security features from raw email text."""

    URL_PATTERN = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    IP_URL_PATTERN = re.compile(
        r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    )
    HTML_ANCHOR_PATTERN = re.compile(
        r'<a\s+[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>([^<]+)</a>',
        re.IGNORECASE | re.DOTALL
    )

    def extract(self, email_text: str) -> dict:
        """
        Extract all security features from an email.

        Returns a dictionary of 15 numeric features suitable for ML training.
        """
        text_lower = email_text.lower()
        urls = self._extract_urls(email_text)

        return {
            # URL-based features
            'url_count': len(urls),
            'ip_url_count': len(self.IP_URL_PATTERN.findall(email_text)),
            'suspicious_tld_count': self._count_suspicious_tlds(urls),
            'url_shortener_count': self._count_url_shorteners(urls),
            'link_mismatch_count': self._count_link_mismatches(email_text),
            'https_ratio': self._https_ratio(urls),

            # Social engineering features
            'urgency_keyword_count': self._count_keywords(text_lower, URGENCY_KEYWORDS),
            'financial_lure_count': self._count_keywords(text_lower, FINANCIAL_LURES),
            'brand_mention_count': self._count_keywords(text_lower, IMPERSONATED_BRANDS),
            'generic_greeting': int(self._has_generic_greeting(text_lower)),
            'excessive_caps_ratio': self._caps_ratio(email_text),
            'exclamation_count': email_text.count('!'),

            # Structural / formatting features
            'has_html': int('<html' in text_lower or '<body' in text_lower),
            'attachment_mention': int(any(
                w in text_lower for w in ['attachment', 'attached', '.zip', '.exe', '.docm']
            )),
            'text_length': len(email_text),
        }

    def _extract_urls(self, text: str) -> list:
        return self.URL_PATTERN.findall(text)

    def _count_suspicious_tlds(self, urls: list) -> int:
        count = 0
        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
                if tld in SUSPICIOUS_TLDS:
                    count += 1
            except Exception:
                continue
        return count

    def _count_url_shorteners(self, urls: list) -> int:
        shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'}
        count = 0
        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                if any(s in domain for s in shorteners):
                    count += 1
            except Exception:
                continue
        return count

    def _count_link_mismatches(self, text: str) -> int:
        """
        Detect <a href="real.com">fake.com</a> patterns — a classic phishing tactic
        where displayed text and actual link target differ.
        """
        mismatches = 0
        for href, display in self.HTML_ANCHOR_PATTERN.findall(text):
            href_lower = href.lower().strip()
            display_lower = display.lower().strip()

            if href_lower.startswith(('mailto:', 'tel:', '#')):
                continue
            if not display_lower or display_lower in href_lower:
                continue

            try:
                href_domain = urlparse(href_lower).netloc.replace('www.', '')
                # If display looks like a URL/domain and doesn't match href domain
                if '.' in display_lower and href_domain and href_domain not in display_lower:
                    mismatches += 1
            except Exception:
                continue
        return mismatches

    def _https_ratio(self, urls: list) -> float:
        if not urls:
            return 0.0
        https_count = sum(1 for u in urls if u.lower().startswith('https://'))
        return https_count / len(urls)

    def _count_keywords(self, text_lower: str, keywords: list) -> int:
        return sum(1 for kw in keywords if kw in text_lower)

    def _has_generic_greeting(self, text_lower: str) -> bool:
        return any(g in text_lower for g in GENERIC_GREETINGS)

    def _caps_ratio(self, text: str) -> float:
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c.isupper()) / len(letters)


if __name__ == '__main__':
    # Quick sanity check
    extractor = SecurityFeatureExtractor()
    sample = """Dear Customer,

    URGENT: Your PayPal account has been suspended due to unusual activity!
    Please verify immediately at <a href="http://paypal-verify.tk/login">paypal.com</a>
    or your account will expire within 24 hours.

    Click here: http://bit.ly/xyz123"""

    features = extractor.extract(sample)
    print("Extracted features:")
    for name, value in features.items():
        print(f"  {name:30s} = {value}")
