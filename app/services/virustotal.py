import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.core.config import settings


VIRUSTOTAL_URL_SUBMIT_API_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_ANALYSIS_API_URL = "https://www.virustotal.com/api/v3/analyses"
VIRUSTOTAL_MALICIOUS_REASON = "VirusTotal a raportat acest URL ca malițios prin mai mulți vendori de securitate."
VIRUSTOTAL_SUSPICIOUS_REASON = "VirusTotal a raportat detecții suspecte pentru acest URL."


def check_virustotal_url(url: str) -> dict:
    """Submit a URL to VirusTotal and return compact detection stats if available."""
    api_key = settings.VIRUSTOTAL_API_KEY

    # URL analysis must keep working in local/dev environments without credentials.
    if not api_key:
        return {"checked": False}

    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    submit_request = Request(
        VIRUSTOTAL_URL_SUBMIT_API_URL,
        data=urlencode({"url": url}).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        # VirusTotal can be slower than local checks, but should not stall analysis.
        with urlopen(submit_request, timeout=8) as submit_response:
            submit_body = json.loads(submit_response.read().decode("utf-8"))

        analysis_id = submit_body["data"]["id"]
        analysis_request = Request(
            f"{VIRUSTOTAL_ANALYSIS_API_URL}/{analysis_id}",
            headers={"x-apikey": api_key},
            method="GET",
        )

        with urlopen(analysis_request, timeout=8) as analysis_response:
            analysis_body = json.loads(analysis_response.read().decode("utf-8"))

        stats = analysis_body["data"]["attributes"]["stats"]
    except (KeyError, TypeError, ValueError, HTTPError, URLError, OSError, json.JSONDecodeError):
        return {"checked": False}

    return {
        "checked": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
    }
