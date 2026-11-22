import re
import sys
from email import policy
from email.parser import BytesParser

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+")


def parse_bytes(data):
    msg = BytesParser(policy=policy.default).parsebytes(data)

    body_part = msg.get_body(preferencelist=("plain", "html"))
    body = body_part.get_content() if body_part else ""

    links = URL_PATTERN.findall(body)

    attachments = [
        part.get_filename()
        for part in msg.iter_attachments()
        if part.get_filename()
    ]

    return {
        "from": msg["From"],
        "reply_to": msg["Reply-To"],
        "subject": msg["Subject"],
        "body": body,
        "links": links,
        "attachments": attachments,
    }


def parse_email(path):
    with open(path, "rb") as f:
        return parse_bytes(f.read())


if __name__ == "__main__":
    result = parse_email(sys.argv[1])
    for key, value in result.items():
        print(f"{key}: {value!r}")