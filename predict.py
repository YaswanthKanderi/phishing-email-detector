#!/usr/bin/env python3
"""
Phishing Detector - CLI Prediction Tool
========================================

Classify an email as phishing or legitimate, with a breakdown of the
security signals that drove the decision.

Usage:
    python predict.py --email examples/sample_phishing.txt
    python predict.py --text "Your account is suspended! Click http://bit.ly/xyz"
    echo "some email text" | python predict.py --stdin
"""

import argparse
import sys
from pathlib import Path

from detector.model import PhishingDetector


# ANSI colour codes for pretty CLI output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'


def format_result(result: dict) -> str:
    """Format the prediction result as a human-readable CLI report."""
    verdict = result['verdict']
    prob = result['phishing_probability']
    signals = result['security_signals']

    # Colour-code the verdict
    if verdict == 'PHISHING':
        badge = f"{RED}{BOLD}⚠  PHISHING DETECTED{RESET}"
    else:
        badge = f"{GREEN}{BOLD}✓  LEGITIMATE{RESET}"

    lines = [
        "",
        "=" * 60,
        f"  {badge}",
        "=" * 60,
        f"  Phishing Probability:  {CYAN}{prob:.1%}{RESET}",
        f"  Confidence:            {result['confidence']:.1%}",
        "",
        f"{BOLD}Security Signals Detected:{RESET}",
        "-" * 60,
    ]

    # Highlight suspicious signals
    warnings = []
    if signals['url_count'] > 0:
        warnings.append(f"  • URLs found:                {signals['url_count']}")
    if signals['ip_url_count'] > 0:
        warnings.append(f"  {RED}• Raw IP URLs:               {signals['ip_url_count']} ⚠{RESET}")
    if signals['suspicious_tld_count'] > 0:
        warnings.append(f"  {RED}• Suspicious TLDs (.tk/.ml): {signals['suspicious_tld_count']} ⚠{RESET}")
    if signals['url_shortener_count'] > 0:
        warnings.append(f"  {YELLOW}• URL shorteners:            {signals['url_shortener_count']} ⚠{RESET}")
    if signals['link_mismatch_count'] > 0:
        warnings.append(f"  {RED}• Display/link mismatches:   {signals['link_mismatch_count']} ⚠{RESET}")
    if signals['urgency_keyword_count'] > 0:
        warnings.append(f"  {YELLOW}• Urgency keywords:          {signals['urgency_keyword_count']} ⚠{RESET}")
    if signals['financial_lure_count'] > 0:
        warnings.append(f"  {YELLOW}• Financial lures:           {signals['financial_lure_count']} ⚠{RESET}")
    if signals['brand_mention_count'] > 0:
        warnings.append(f"  • Brand mentions:            {signals['brand_mention_count']}")
    if signals['generic_greeting']:
        warnings.append(f"  {YELLOW}• Generic greeting:          yes ⚠{RESET}")
    if signals['attachment_mention']:
        warnings.append(f"  {YELLOW}• Suspicious attachment:     yes ⚠{RESET}")
    if signals['excessive_caps_ratio'] > 0.15:
        warnings.append(f"  {YELLOW}• Excessive caps:            {signals['excessive_caps_ratio']:.1%} ⚠{RESET}")

    if warnings:
        lines.extend(warnings)
    else:
        lines.append(f"  {GREEN}No suspicious signals detected.{RESET}")

    lines.extend([
        "",
        "=" * 60,
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description='Classify an email as phishing or legitimate')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--email', type=str, help='Path to a text file containing email content')
    group.add_argument('--text', type=str, help='Email text passed directly as a string')
    group.add_argument('--stdin', action='store_true', help='Read email text from stdin')
    parser.add_argument('--model', type=str, default='models/phishing_detector.pkl',
                        help='Path to the trained model')
    args = parser.parse_args()

    # Load email content from the requested source
    if args.email:
        email_path = Path(args.email)
        if not email_path.exists():
            print(f"❌ Email file not found: {email_path}")
            sys.exit(1)
        email_text = email_path.read_text(encoding='utf-8')
    elif args.text:
        email_text = args.text
    else:
        email_text = sys.stdin.read()

    # Load model
    model_path = Path(args.model)
    if not model_path.exists():
        print(f"❌ Model not found at {model_path}")
        print(f"   Train one first: python train.py")
        sys.exit(1)

    detector = PhishingDetector().load(model_path)
    result = detector.predict(email_text)
    print(format_result(result))

    # Exit code reflects the classification for use in shell pipelines
    sys.exit(1 if result['is_phishing'] else 0)


if __name__ == '__main__':
    main()
