import ipaddress
import re
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlparse


RiskLevel = Literal["safe", "suspicious", "dangerous"]

SHORTENED_LINK_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rebrand.ly",
    "cutt.ly",
    "is.gd",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".work", ".info", ".tk", ".ml"}

OFFICIAL_DOMAINS = {
    "vodafone.ro",
    "orange.ro",
    "digi.ro",
    "rcs-rds.ro",
    "emag.ro",
    "lidl.ro",
    "kaufland.ro",
    "carrefour.ro",
    "altex.ro",
    "flanco.ro",
    "anaf.ro",
    "fancourier.ro",
    "sameday.ro",
    "cargus.ro",
    "dhl.com",
    "dhl.ro",
    "dpd.com",
    "dpd.ro",
    "gls-group.com",
    "gls-romania.ro",
    "netflix.com",
    "google.com",
    "accounts.google.com",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "live.com",
    "outlook.com",
    "facebook.com",
    "meta.com",
    "instagram.com",
    "whatsapp.com",
    "binance.com",
    "crypto.com",
    "coinbase.com",
    "kraken.com",
    "metamask.io",
    "trustwallet.com",
    "blockchain.com",
    "okx.com",
    "bybit.com",
    "kucoin.com",
}

KNOWN_BRANDS = {
    "vodafone",
    "orange",
    "digi",
    "emag",
    "lidl",
    "kaufland",
    "carrefour",
    "altex",
    "flanco",
    "anaf",
    "fancourier",
    "fan courier",
    "sameday",
    "cargus",
    "dhl",
    "dpd",
    "gls",
    "netflix",
    "google",
    "apple",
    "microsoft",
    "facebook",
    "meta",
    "instagram",
    "whatsapp",
    "binance",
    "crypto.com",
    "coinbase",
    "kraken",
    "metamask",
    "trustwallet",
    "trust wallet",
    "blockchain",
    "okx",
    "bybit",
    "kucoin",
}

SUSPICIOUS_KEYWORDS = {
    "oferta",
    "promotie",
    "promo",
    "bonus",
    "castig",
    "castiga",
    "premiu",
    "voucher",
    "gratuit",
    "gratis",
    "reducere",
    "urgent",
    "plata",
    "factura",
    "verificare",
    "login",
    "secure",
    "securizare",
    "account",
    "cont",
    "wallet",
    "crypto",
    "claim",
    "reward",
    "free",
    "win",
    "prize",
    "gift",
}

SENSITIVE_PATH_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "payment",
    "pay",
    "update",
    "reset",
    "password",
    "billing",
    "invoice",
    "wallet",
    "auth",
    "authenticate",
}

SUSPICIOUS_QUERY_PARAMS = {
    "token",
    "session",
    "redirect",
    "url",
    "next",
    "continue",
    "login",
    "auth",
    "password",
    "otp",
    "code",
}

SUSPICIOUS_FILE_EXTENSIONS = {".exe", ".apk", ".scr", ".bat", ".cmd", ".zip", ".rar"}
UNUSUAL_PORTS = {8080, 4443, 8888, 1337}
ENCODED_MARKERS = ("%2f", "%3a", "%40", "%2e")

REASON_PENALTIES = {
    "URL-ul nu folosește HTTPS.": 15,
    "URL-ul combină lipsa HTTPS cu termeni suspecti, ceea ce crește riscul.": 15,
    "URL-ul conține termeni frecvent folosiți în campanii de phishing sau scam.": 20,
    "Linkul este scurtat și poate ascunde destinația reală.": 25,
    "URL-ul folosește un domeniu cu extensie frecvent întâlnită în campanii suspecte.": 20,
    "Domeniul conține prea multe cratime.": 15,
    "URL-ul este neobișnuit de lung.": 15,
    "URL-ul folosește o adresă IP în locul unui domeniu.": 30,
    "URL-ul folosește simbolul @ pentru a ascunde domeniul real.": 55,
    "URL-ul conține caractere codificate care pot ascunde destinația reală.": 15,
    "URL-ul are prea multe subdomenii.": 15,
    "Domeniul pare să imite un brand cunoscut.": 35,
    "URL-ul folosește un domeniu oficial ca subdomeniu pentru a părea credibil.": 35,
    "URL-ul cere acțiuni sensibile precum autentificare, plată sau verificare pe un domeniu neoficial.": 25,
    "Domeniul conține multe cifre sau pare generat automat.": 15,
    "Domeniul folosește punycode, o tehnică ce poate ascunde imitarea unui brand.": 30,
    "URL-ul conține parametri sensibili sau redirecționări suspecte.": 15,
    "URL-ul pare să conțină o redirecționare către alt site.": 25,
    "URL-ul are o structură neobișnuit de lungă.": 10,
    "URL-ul indică un fișier potențial periculos.": 60,
    "Domeniul pare să folosească typosquatting pentru a imita un brand.": 55,
    "URL-ul folosește un port neobișnuit.": 15,
    "URL-ul indică o adresă locală sau privată, suspectă într-un mesaj primit.": 25,
}

RECOMMENDATIONS = {
    "safe": "Linkul pare sigur, dar verifică mereu sursa oficială.",
    "suspicious": "Linkul are semnale suspecte. Verifică manual domeniul înainte de accesare.",
    "dangerous": "Linkul pare periculos. Nu îl accesa și verifică sursa prin canale oficiale.",
}


def normalize_url(raw_url: str) -> tuple[str, str]:
    """Return the cleaned original URL and a parseable URL with a scheme."""
    cleaned_url = raw_url.strip().lower()
    parseable_url = cleaned_url if "://" in cleaned_url else f"http://{cleaned_url}"

    return cleaned_url, parseable_url


def normalize_hostname(hostname: str | None) -> str:
    if not hostname:
        return ""

    return hostname.lower().strip(".").removeprefix("www.")


def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return True


def is_private_or_local_host(hostname: str) -> bool:
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return ip_address.is_private or ip_address.is_loopback or ip_address.is_link_local


def is_official_domain(domain: str) -> bool:
    return any(domain == official_domain or domain.endswith(f".{official_domain}") for official_domain in OFFICIAL_DOMAINS)


def compact_text(value: str) -> str:
    return value.replace("-", "").replace(".", "").replace(" ", "")


def contains_keyword(value: str, keywords: set[str]) -> bool:
    return any(keyword in value for keyword in keywords)


def main_domain_label(domain: str) -> str:
    return domain.split(".")[0]


def has_too_many_subdomains(domain: str) -> bool:
    labels = domain.split(".")

    # Four or more labels means there are at least two subdomain layers.
    return len(labels) >= 4


def has_official_domain_as_fake_subdomain(domain: str) -> bool:
    domain_labels = domain.split(".")

    for official_domain in OFFICIAL_DOMAINS:
        official_labels = official_domain.split(".")
        official_length = len(official_labels)

        for index in range(0, len(domain_labels) - official_length):
            if domain_labels[index : index + official_length] == official_labels:
                return True

    return False


def imitates_known_brand(domain: str) -> bool:
    if is_official_domain(domain):
        return False

    compact_domain = compact_text(domain)

    for brand in KNOWN_BRANDS:
        if compact_text(brand) in compact_domain:
            return True

    return False


def collapse_repeated_letters(value: str) -> str:
    return re.sub(r"([a-z])\1+", r"\1", value)


def has_typosquatting(domain: str) -> bool:
    if is_official_domain(domain):
        return False

    compact_domain = compact_text(domain)
    leet_domain = compact_domain.replace("0", "o")
    leet_domain_l = leet_domain.replace("1", "l")
    leet_domain_i = leet_domain.replace("1", "i")
    collapsed_domain = collapse_repeated_letters(leet_domain)

    for brand in KNOWN_BRANDS:
        compact_brand = compact_text(brand)

        # If the brand is already spelled normally, this is impersonation, not typosquatting.
        if compact_brand in compact_domain:
            continue

        # These variants catch common tricks like g00gle, vodaf0ne, and faceboook.
        if compact_brand in leet_domain_l or compact_brand in leet_domain_i or compact_brand in collapsed_domain:
            return True

    return False


def is_numeric_or_random_looking(domain: str) -> bool:
    label = main_domain_label(domain)
    digit_count = sum(character.isdigit() for character in label)

    if digit_count >= 4 or (len(label) >= 6 and digit_count / len(label) >= 0.3):
        return True

    # Long consonant-heavy labels are often generated automatically.
    consonant_runs = re.findall(r"[bcdfghjklmnpqrstvwxyz]{6,}", label)
    return len(label) >= 12 and bool(consonant_runs)


def has_redirect_url_in_query(query: str) -> bool:
    decoded_query = unquote(query.lower())

    if re.search(r"https?://", decoded_query):
        return True

    for parameter_name, parameter_value in parse_qsl(query, keep_blank_values=True):
        parameter_name = parameter_name.lower()
        parameter_value = unquote(parameter_value.lower())

        if parameter_name in {"redirect", "url", "next", "continue"} and (
            "://" in parameter_value or "." in parameter_value
        ):
            return True

    return False


def has_suspicious_query_parameter(query: str) -> bool:
    for parameter_name, _ in parse_qsl(query, keep_blank_values=True):
        if parameter_name.lower() in SUSPICIOUS_QUERY_PARAMS:
            return True

    return False


def has_suspicious_file_extension(path: str) -> bool:
    lowered_path = path.lower()
    return any(lowered_path.endswith(extension) for extension in SUSPICIOUS_FILE_EXTENSIONS)


def get_url_port(parsed_url) -> int | None:
    try:
        return parsed_url.port
    except ValueError:
        return None


def get_path_segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def get_risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "safe"

    if score >= 45:
        return "suspicious"

    return "dangerous"


def calculate_url_trust_score(reasons: list[str]) -> int:
    total_penalty = sum(REASON_PENALTIES[reason] for reason in reasons)
    return max(0, min(100, 100 - total_penalty))


def analyze_url(raw_url: str) -> dict[str, int | RiskLevel | list[str] | str]:
    reasons: list[str] = []
    cleaned_url, parseable_url = normalize_url(raw_url)
    parsed_url = urlparse(parseable_url)
    domain = normalize_hostname(parsed_url.hostname)
    scheme = parsed_url.scheme.lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    domain_and_path = f"{domain} {path}"
    is_official = is_official_domain(domain)
    is_ip = is_ip_address(domain)
    has_suspicious_keyword = contains_keyword(domain_and_path, SUSPICIOUS_KEYWORDS)

    # HTTPS protects the connection. Missing HTTPS is still a meaningful warning.
    if scheme != "https" and not is_official:
        add_reason(reasons, "URL-ul nu folosește HTTPS.")

    # Userinfo before @ can make a fake URL display an official-looking domain first.
    if "@" in parsed_url.netloc:
        add_reason(reasons, "URL-ul folosește simbolul @ pentru a ascunde domeniul real.")

    # Shortened links hide the final destination, even when the shortener itself is legitimate.
    if domain in SHORTENED_LINK_DOMAINS:
        add_reason(reasons, "Linkul este scurtat și poate ascunde destinația reală.")

    # Official domains and their legitimate subdomains avoid weak heuristic penalties.
    if not is_official:
        # These TLDs are frequently abused because they are cheap and easy to register.
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            add_reason(reasons, "URL-ul folosește un domeniu cu extensie frecvent întâlnită în campanii suspecte.")

        # Many hyphens in the main label often signal fake campaign domains.
        if main_domain_label(domain).count("-") >= 2:
            add_reason(reasons, "Domeniul conține prea multe cratime.")

        # Deep subdomains can bury the real registered domain.
        if domain and not is_ip and has_too_many_subdomains(domain):
            add_reason(reasons, "URL-ul are prea multe subdomenii.")

        # Brand names on unofficial domains are a strong phishing signal.
        if domain and imitates_known_brand(domain):
            add_reason(reasons, "Domeniul pare să imite un brand cunoscut.")

        # Fake domains sometimes place a real official domain at the front.
        if domain and has_official_domain_as_fake_subdomain(domain):
            add_reason(reasons, "URL-ul folosește un domeniu oficial ca subdomeniu pentru a părea credibil.")

        # Scam campaigns often use urgent, prize, login, wallet, or payment wording.
        if has_suspicious_keyword:
            add_reason(reasons, "URL-ul conține termeni frecvent folosiți în campanii de phishing sau scam.")

        # HTTP plus scam wording is riskier than either signal by itself.
        if scheme != "https" and has_suspicious_keyword:
            add_reason(reasons, "URL-ul combină lipsa HTTPS cu termeni suspecti, ceea ce crește riscul.")

        # Login/payment/security flows should happen only on official domains.
        if contains_keyword(path, SENSITIVE_PATH_KEYWORDS):
            add_reason(
                reasons,
                "URL-ul cere acțiuni sensibile precum autentificare, plată sau verificare pe un domeniu neoficial.",
            )

        # Random-looking labels are common in throwaway phishing infrastructure.
        if domain and not is_ip and is_numeric_or_random_looking(domain):
            add_reason(reasons, "Domeniul conține multe cifre sau pare generat automat.")

        # Typosquatting uses tiny spelling changes to imitate trusted brands.
        if domain and has_typosquatting(domain):
            add_reason(reasons, "Domeniul pare să folosească typosquatting pentru a imita un brand.")

    # Very long URLs can hide redirects, payloads, or tracking data.
    if len(cleaned_url) > 120:
        add_reason(reasons, "URL-ul este neobișnuit de lung.")

    # IP-based links are unusual in messages from real companies.
    if is_ip:
        add_reason(reasons, "URL-ul folosește o adresă IP în locul unui domeniu.")

    # Private/local addresses should not usually appear in public SMS or email links.
    if domain and is_private_or_local_host(domain):
        add_reason(reasons, "URL-ul indică o adresă locală sau privată, suspectă într-un mesaj primit.")

    # Encoded separators can disguise nested URLs or the real destination.
    if any(marker in cleaned_url for marker in ENCODED_MARKERS):
        add_reason(reasons, "URL-ul conține caractere codificate care pot ascunde destinația reală.")

    # Punycode can be used for IDN homograph attacks against brand names.
    if "xn--" in domain:
        add_reason(reasons, "Domeniul folosește punycode, o tehnică ce poate ascunde imitarea unui brand.")

    # Sensitive query parameters often carry sessions, redirects, or verification codes.
    if query and has_suspicious_query_parameter(query):
        add_reason(reasons, "URL-ul conține parametri sensibili sau redirecționări suspecte.")

    # A URL embedded inside a query usually means the link redirects somewhere else.
    if query and has_redirect_url_in_query(query):
        add_reason(reasons, "URL-ul pare să conțină o redirecționare către alt site.")

    # Many path segments can hide the important part of the destination.
    if len(get_path_segments(path)) > 5:
        add_reason(reasons, "URL-ul are o structură neobișnuit de lungă.")

    # Executables and archives are dangerous when sent as links.
    if has_suspicious_file_extension(path):
        add_reason(reasons, "URL-ul indică un fișier potențial periculos.")

    # Odd ports are uncommon in normal consumer-facing links.
    if get_url_port(parsed_url) in UNUSUAL_PORTS:
        add_reason(reasons, "URL-ul folosește un port neobișnuit.")

    trust_score = calculate_url_trust_score(reasons)
    risk = get_risk_level(trust_score)

    return {
        "trust_score": trust_score,
        "risk": risk,
        "reasons": reasons,
        "recommendation": RECOMMENDATIONS[risk],
    }
