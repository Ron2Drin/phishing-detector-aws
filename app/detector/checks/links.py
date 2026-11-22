import ipaddress
import sys
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rebrand.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "ru", "tk", "zip", "click", "gq", "loan", "work"}


def check_links(links):
    findings = []
    for url in links:
        host = urlparse(url).hostname or ""

        if _is_ip(host):
            findings.append({"check": "links", "points": 25,
                             "reason": f"Link points to an IP address: {url}"})
        if host in SHORTENERS:
            findings.append({"check": "links", "points": 15,
                             "reason": f"URL shortener hides the real destination: {url}"})
        if host.split(".")[-1] in SUSPICIOUS_TLDS:
            findings.append({"check": "links", "points": 15,
                             "reason": f"Uncommon top-level domain: {host}"})
        if host.startswith("xn--") or ".xn--" in host:
            findings.append({"check": "links", "points": 20,
                             "reason": f"Punycode domain (look-alike letters): {host}"})
        if url.startswith("http://"):
            findings.append({"check": "links", "points": 5,
                             "reason": f"Link is not encrypted (http): {url}"})
    return findings


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    from app.detector.parser import parse_email
    email = parse_email(sys.argv[1])
    for finding in check_links(email["links"]):
        print(finding)