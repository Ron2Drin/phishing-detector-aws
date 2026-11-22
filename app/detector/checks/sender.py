import sys
from difflib import SequenceMatcher
from email.utils import parseaddr

BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
}
LOOKALIKE_CHARS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


def check_sender(from_header, reply_to_header):
    findings = []
    display_name, from_addr = parseaddr(from_header or "")
    from_domain = _domain(from_addr)

    brand = _impersonated_brand(from_domain)
    if brand:
        findings.append({"check": "sender", "points": 30,
                         "reason": f"Sender domain '{from_domain}' imitates {BRANDS[brand]}"})

    name = display_name.lower().replace(" ", "")
    for brand_name, real_domain in BRANDS.items():
        if brand_name in name and not from_domain.endswith(real_domain):
            findings.append({"check": "sender", "points": 20,
                             "reason": f"Display name '{display_name}' claims {brand_name} but sender is @{from_domain}"})
            break

    if reply_to_header:
        _, reply_addr = parseaddr(reply_to_header)
        reply_domain = _domain(reply_addr)
        if reply_domain and reply_domain != from_domain:
            findings.append({"check": "sender", "points": 20,
                             "reason": f"Reply-To domain '{reply_domain}' differs from sender '{from_domain}'"})
    return findings


def _domain(address):
    return address.split("@")[-1].lower() if "@" in address else ""


def _impersonated_brand(domain):
    for real_domain in BRANDS.values():
        if domain == real_domain or domain.endswith("." + real_domain):
            return None
    first_label = domain.split(".")[0].translate(LOOKALIKE_CHARS)
    for brand in BRANDS:
        if brand in first_label or SequenceMatcher(None, first_label, brand).ratio() >= 0.8:
            return brand
    return None


if __name__ == "__main__":
    from app.detector.parser import parse_email
    email = parse_email(sys.argv[1])
    for finding in check_sender(email["from"], email["reply_to"]):
        print(finding)