import re
import sys

URGENCY = ["urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
           "suspended", "will be closed", "locked", "final notice", "unusual activity"]
SENSITIVE = ["password", "credit card", "card number", "cvv", "social security",
             "bank account", "pin", "login details", "verify your identity"]
GENERIC_GREETINGS = ["dear customer", "dear user", "dear client", "dear account holder"]


def check_wording(subject, body):
    text = f"{subject or ''} {body or ''}".lower()
    findings = []

    urgent = [w for w in URGENCY if w in text]
    if urgent:
        findings.append({"check": "wording", "points": min(5 * len(urgent), 20),
                         "reason": f"Urgent or threatening language: {', '.join(urgent)}"})

    sensitive = [w for w in SENSITIVE if re.search(rf"\b{re.escape(w)}\b", text)]
    if sensitive:
        findings.append({"check": "wording", "points": 20,
                         "reason": f"Asks for sensitive information: {', '.join(sensitive)}"})

    greeting = next((g for g in GENERIC_GREETINGS if g in text), None)
    if greeting:
        findings.append({"check": "wording", "points": 5,
                         "reason": f"Generic greeting: '{greeting}'"})
    return findings


if __name__ == "__main__":
    from app.detector.parser import parse_email
    email = parse_email(sys.argv[1])
    for finding in check_wording(email["subject"], email["body"]):
        print(finding)
        