"""
Unit tests for the Phishing Email Detector.

Run with:
    python -m pytest tests/
    python -m unittest tests.test_detector
"""

import unittest

from detector.features import SecurityFeatureExtractor
from detector.preprocessor import EmailPreprocessor


class TestSecurityFeatures(unittest.TestCase):
    def setUp(self):
        self.extractor = SecurityFeatureExtractor()

    def test_detects_urls(self):
        email = "Visit http://example.com and http://test.com/path"
        features = self.extractor.extract(email)
        self.assertEqual(features['url_count'], 2)

    def test_detects_suspicious_tlds(self):
        email = "Click http://bank-verify.tk/login or http://secure.ml/auth"
        features = self.extractor.extract(email)
        self.assertEqual(features['suspicious_tld_count'], 2)

    def test_detects_ip_urls(self):
        email = "Go to http://192.168.1.1/admin to verify"
        features = self.extractor.extract(email)
        self.assertEqual(features['ip_url_count'], 1)

    def test_detects_url_shorteners(self):
        email = "Click http://bit.ly/abc123 or http://tinyurl.com/xyz"
        features = self.extractor.extract(email)
        self.assertEqual(features['url_shortener_count'], 2)

    def test_detects_link_mismatch(self):
        email = 'Click <a href="http://malicious.tk/login">www.paypal.com</a> to verify'
        features = self.extractor.extract(email)
        self.assertGreaterEqual(features['link_mismatch_count'], 1)

    def test_detects_urgency_keywords(self):
        email = "URGENT: Your account will be suspended immediately! Act now."
        features = self.extractor.extract(email)
        self.assertGreater(features['urgency_keyword_count'], 0)

    def test_detects_generic_greeting(self):
        email = "Dear Customer, please update your details"
        features = self.extractor.extract(email)
        self.assertEqual(features['generic_greeting'], 1)

    def test_no_false_positives_on_clean_email(self):
        email = "Hi Sarah, here's the quarterly report as requested. Let me know if you have any questions. Best, Mike"
        features = self.extractor.extract(email)
        self.assertEqual(features['url_count'], 0)
        self.assertEqual(features['suspicious_tld_count'], 0)
        self.assertEqual(features['generic_greeting'], 0)


class TestPreprocessor(unittest.TestCase):
    def setUp(self):
        self.preprocessor = EmailPreprocessor()

    def test_removes_html_tags(self):
        text = "<html><body>Hello <b>world</b></body></html>"
        cleaned = self.preprocessor.clean(text)
        self.assertNotIn('<', cleaned)
        self.assertIn('hello', cleaned)

    def test_replaces_urls_with_token(self):
        text = "Check http://example.com for details"
        cleaned = self.preprocessor.clean(text)
        self.assertIn('urltoken', cleaned)
        self.assertNotIn('http', cleaned)

    def test_replaces_emails_with_token(self):
        text = "Contact me at john@example.com"
        cleaned = self.preprocessor.clean(text)
        self.assertIn('emailtoken', cleaned)

    def test_handles_empty_input(self):
        self.assertEqual(self.preprocessor.clean(''), '')
        self.assertEqual(self.preprocessor.clean(None), '')

    def test_lowercases_text(self):
        cleaned = self.preprocessor.clean("HELLO World")
        self.assertEqual(cleaned, 'hello world')


if __name__ == '__main__':
    unittest.main()
