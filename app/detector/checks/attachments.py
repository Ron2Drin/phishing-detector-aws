import sys

DANGEROUS = {"exe", "scr", "js", "vbs", "bat", "cmd", "msi", "jar", "ps1", "hta", "lnk", "iso"}
MACRO = {"docm", "xlsm", "pptm"}
ARCHIVES = {"zip", "rar", "7z"}
HARMLESS_LOOKING = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}


def check_attachments(filenames):
    findings = []
    for name in filenames:
        parts = name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""

        if ext in DANGEROUS:
            findings.append({"check": "attachments", "points": 30,
                             "reason": f"Executable attachment: {name}"})
        if len(parts) >= 3 and parts[-2] in HARMLESS_LOOKING and ext in DANGEROUS:
            findings.append({"check": "attachments", "points": 20,
                             "reason": f"Double extension hides the real file type: {name}"})
        if ext in MACRO:
            findings.append({"check": "attachments", "points": 25,
                             "reason": f"Office file with macros: {name}"})
        if ext in ARCHIVES:
            findings.append({"check": "attachments", "points": 10,
                             "reason": f"Compressed archive may hide malware: {name}"})
    return findings


if __name__ == "__main__":
    from app.detector.parser import parse_email
    email = parse_email(sys.argv[1])
    for finding in check_attachments(email["attachments"]):
        print(finding)