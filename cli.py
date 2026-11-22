import json
import sys

from app.detector.scoring import analyze
from app.history import init_db, list_scans, save_scan

ICONS = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "PHISHING": "🚨"}


def scan(path):
    with open(path, "rb") as f:
        result = analyze(f.read())
    save_scan(path, result)

    print(f"\n{ICONS[result['verdict']]} Verdict: {result['verdict']}  (score: {result['score']}/100)")
    print(f"   From:    {result['from']}")
    print(f"   Subject: {result['subject']}\n")

    if not result["findings"]:
        print("No phishing indicators detected.")
        return

    print("Detected indicators:")
    for f in sorted(result["findings"], key=lambda f: -f["points"]):
        print(f"  [+{f['points']:>2}] ({f['check']}) {f['reason']}")


def show_history():
    rows = list_scans()
    if not rows:
        print("No scans yet.")
        return
    print(f"\n{'ID':>3}  {'When (UTC)':<19}  {'Verdict':<10}  {'Score':>5}  Source")
    for r in rows:
        when = r["scanned_at"].strftime("%Y-%m-%d %H:%M:%S")
        count = len(json.loads(r["findings"]))
        print(f"{r['id']:>3}  {when:<19}  {r['verdict']:<10}  {r['score']:>5}  {r['source']}  ({count} indicators)")


def main():
    init_db()
    if len(sys.argv) == 2 and sys.argv[1] == "--history":
        show_history()
    elif len(sys.argv) == 2:
        scan(sys.argv[1])
    else:
        print("Usage: python cli.py <email-file>")
        print("       python cli.py --history")
        sys.exit(1)


if __name__ == "__main__":
    main()
