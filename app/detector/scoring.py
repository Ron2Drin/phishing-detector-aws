from app.detector.checks.attachments import check_attachments
from app.detector.checks.links import check_links
from app.detector.checks.sender import check_sender
from app.detector.checks.wording import check_wording
from app.detector.parser import parse_bytes

SUSPICIOUS_FROM = 30
PHISHING_FROM = 70


def analyze(raw_email):
    email = parse_bytes(raw_email)

    findings = (
        check_sender(email["from"], email["reply_to"])
        + check_links(email["links"])
        + check_wording(email["subject"], email["body"])
        + check_attachments(email["attachments"])
    )

    score = min(sum(f["points"] for f in findings), 100)

    if score >= PHISHING_FROM:
        verdict = "PHISHING"
    elif score >= SUSPICIOUS_FROM:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "from": email["from"],
        "subject": email["subject"],
    }