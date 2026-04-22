"""
Email Text Preprocessor
-----------------------
Cleans raw email text for TF-IDF vectorisation. Handles HTML stripping,
URL normalisation, and basic normalisation while preserving signal.
"""

import re
import html


class EmailPreprocessor:
    """Cleans email text for NLP processing."""

    HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
    URL_PATTERN = re.compile(r'http[s]?://\S+')
    EMAIL_PATTERN = re.compile(r'\S+@\S+\.\S+')
    MULTI_SPACE_PATTERN = re.compile(r'\s+')
    NON_ALPHA_PATTERN = re.compile(r'[^a-zA-Z\s]')

    def clean(self, text: str) -> str:
        """
        Apply the full cleaning pipeline.

        Replaces URLs and emails with tokens (rather than stripping them
        entirely) so the model can learn 'contains URL' as a signal.
        """
        if not isinstance(text, str):
            return ''

        text = html.unescape(text)
        text = self.HTML_TAG_PATTERN.sub(' ', text)
        text = self.URL_PATTERN.sub(' URLTOKEN ', text)
        text = self.EMAIL_PATTERN.sub(' EMAILTOKEN ', text)
        text = text.lower()
        text = self.NON_ALPHA_PATTERN.sub(' ', text)
        text = self.MULTI_SPACE_PATTERN.sub(' ', text).strip()

        return text


if __name__ == '__main__':
    preprocessor = EmailPreprocessor()
    sample = """<html><body>Hi John,<br>
    Visit http://example.com/login or email us at support@example.com!
    </body></html>"""
    print("Original:", repr(sample))
    print("Cleaned: ", repr(preprocessor.clean(sample)))
