import sys

from app.detector.scoring import analyze

ICONS = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "PHISHING": "🚨"}


def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <email-file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        result = analyze(f.read())

    print(f"\n{ICONS[result['verdict']]} Verdict: {result['verdict']}  (score: {result['score']}/100)")
    print(f"   From:    {result['from']}")
    print(f"   Subject: {result['subject']}\n")

    if not result["findings"]:
        print("No phishing indicators detected.")
        return

    print("Detected indicators:")
    for f in sorted(result["findings"], key=lambda f: -f["points"]):
        print(f"  [+{f['points']:>2}] ({f['check']}) {f['reason']}")


if __name__ == "__main__":
    main()
