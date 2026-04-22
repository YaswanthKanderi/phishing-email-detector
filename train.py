#!/usr/bin/env python3
"""
Phishing Detector - Training Script
====================================

Trains the hybrid phishing detector on the sample dataset and saves the
model to disk for later prediction.

Usage:
    python train.py
    python train.py --data custom_dataset.csv --output models/my_model.pkl
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

from detector.model import PhishingDetector


def main():
    parser = argparse.ArgumentParser(description='Train the phishing email detector')
    parser.add_argument('--data', type=str, default='data/sample_emails.csv',
                        help='Path to training CSV with "text" and "label" columns')
    parser.add_argument('--output', type=str, default='models/phishing_detector.pkl',
                        help='Where to save the trained model')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Fraction of data for held-out test set')
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"❌ Training data not found: {data_path}")
        sys.exit(1)

    print("=" * 60)
    print("  PHISHING EMAIL DETECTOR — TRAINING PIPELINE")
    print("=" * 60)
    print(f"\n→ Loading dataset from {data_path}")

    df = pd.read_csv(data_path)
    required_cols = {'text', 'label'}
    if not required_cols.issubset(df.columns):
        print(f"❌ CSV must contain columns: {required_cols}")
        sys.exit(1)

    print(f"  Total samples: {len(df)}")
    print(f"  Legitimate:    {(df['label'] == 0).sum()}")
    print(f"  Phishing:      {(df['label'] == 1).sum()}")

    detector = PhishingDetector()
    metrics = detector.train(
        emails=df['text'].tolist(),
        labels=df['label'].tolist(),
        test_size=args.test_size,
    )

    detector.save(args.output)

    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE ✓")
    print("=" * 60)
    print(f"  Final Accuracy: {metrics['accuracy']:.2%}")
    print(f"  ROC-AUC Score:  {metrics['roc_auc']:.4f}")
    print(f"\n  Next step: try it out")
    print(f"  $ python predict.py --email examples/sample_phishing.txt")


if __name__ == '__main__':
    main()
