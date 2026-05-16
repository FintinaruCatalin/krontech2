import json
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.core.config import settings


GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GOOGLE_SAFE_BROWSING_REASON = "Google Safe Browsing a identificat acest URL ca potențial periculos."


def check_google_safe_browsing(url: str) -> dict:
    """Check a URL against Google Safe Browsing without making analysis depend on it."""
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    # Missing credentials should never block the local rule-based analyzer.
    if not api_key:
        return {"enabled": False, "matches": []}

    request_body = {
        "client": {
            "clientId": "anti-scam-analyzer",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    request = Request(
        f"{GOOGLE_SAFE_BROWSING_API_URL}?key={api_key}",
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        # A short timeout keeps URL analysis responsive if Google is unreachable.
        with urlopen(request, timeout=4) as response:
            response_body = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError):
        return {"enabled": True, "matches": [], "error": True}

    return {"enabled": True, "matches": response_body.get("matches", [])}
