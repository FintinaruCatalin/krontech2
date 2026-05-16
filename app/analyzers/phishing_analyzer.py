import re
import unicodedata
from urllib.parse import urlparse


ACTION_WORDS = [
    "acceseaza",
    "accesati",
    "intra",
    "intrati",
    "apasa",
    "apasati",
    "completeaza",
    "completati",
    "confirma",
    "confirmati",
    "verifica",
    "verificati",
    "actualizeaza",
    "actualizati",
    "revendica",
    "revendicati",
    "trimite",
    "trimiteti",
    "suna",
    "sunati",
    "plateste",
    "platiti",
    "achita",
    "achitati",
]

URGENCY_THREAT_WORDS = [
    "urgent",
    "imediat",
    "acum",
    "expira",
    "expirat",
    "suspendat",
    "suspendare",
    "blocat",
    "blocare",
    "dezactivat",
    "dezactivare",
    "restrictionat",
    "acces restrictionat",
    "ultima sansa",
    "in 24h",
    "doar azi",
    "astazi",
    "termen limita",
    "timp limitat",
]

PAYMENT_MONEY_WORDS = [
    "plata",
    "plateste",
    "platiti",
    "achita",
    "achitati",
    "taxa",
    "datorie",
    "restanta",
    "transfer",
    "bani",
    "suma",
    "ron",
    "lei",
    "euro",
    "dolari",
]

SENSITIVE_DATA_WORDS = [
    "cnp",
    "cvv",
    "pin",
    "parola",
    "iban",
    "card",
    "date card",
    "cod",
    "otp",
    "cod verificare",
    "cod securitate",
    "cod autentificare",
    "date personale",
    "datele tale",
    "numar card",
]

BANKING_WORDS = [
    "banca",
    "cont",
    "card",
    "tranzactie",
    "debit",
    "credit",
    "sold",
    "iban",
    "autentificare",
    "parola",
    "pin",
    "otp",
    "cod",
    "verificare",
    "confirmare",
    "blocat",
    "suspendat",
    "deblocat",
    "acces restrictionat",
]

DELIVERY_WORDS = [
    "colet",
    "colete",
    "curier",
    "livrare",
    "pachet",
    "comanda",
    "awb",
    "fan courier",
    "sameday",
    "cargus",
    "dhl",
    "dpd",
    "gls",
    "posta romana",
    "taxa livrare",
    "adresa livrare",
    "reprogramare",
    "colet blocat",
]

PRIZE_WORDS = [
    "felicitari",
    "castigator",
    "castigat",
    "loterie",
    "premiu",
    "voucher",
    "cadou",
    "recompensa",
    "oferta",
    "promotie",
    "revendica",
    "revendicati",
    "selectat",
    "calificat",
    "iphone",
    "samsung",
    "telefon",
    "free",
    "win",
    "prize",
    "gift",
]

PROMOTION_WORDS = [
    "oferta",
    "oferta limitata",
    "reducere",
    "reduceri",
    "exclusiv",
    "exclusive",
    "promotie",
    "promotii",
    "discount",
    "deals",
    "deal",
    "gratis",
    "gratuit",
    "bonus",
    "super deals",
]

COMMERCIAL_DOMAIN_WORDS = [
    "deals",
    "discount",
    "promo",
    "oferta",
    "reducere",
    "free",
    "win",
    "gift",
    "bonus",
    "claim",
    "reward",
]

FAMILY_WORDS = ["fiu", "fiica", "copil", "mama", "tata", "sot", "sotie", "frate", "sora", "bunic", "bunica", "nepot", "nepoata", "ruda"]
EMERGENCY_ACCIDENT_WORDS = ["accident", "spital", "urgenta", "ambulanta", "politie", "avocat", "operatie", "interventie", "ranit", "arestat", "problema grava"]

INVOICE_PAYMENT_WORDS = ["factura", "neachitata", "neachitat", "plata restanta", "sold restant", "restanta", "datorie", "suma datorata", "achitare", "achita", "plateste", "platiti", "plata"]
SERVICE_ACCOUNT_WORDS = ["serviciu", "cont", "abonament", "suspendat", "suspendare", "dezactivat", "dezactivare", "blocat", "restrictionat"]
PROVIDER_WORDS = ["orange", "vodafone", "digi", "telekom", "enel", "eon", "hidroelectrica", "electrica", "engie"]

GOVERNMENT_WORDS = ["anaf", "taxe", "impozit", "datorie", "amenda", "poprire", "declaratie", "verificare fiscala", "plata restanta", "guvern", "politie", "judecatorie", "dosar", "sanctiune"]
SUBSCRIPTION_WORDS = ["netflix", "spotify", "youtube", "google", "apple", "microsoft", "meta", "facebook", "instagram", "abonament", "cont suspendat", "plata esuata", "actualizeaza plata", "metoda de plata", "expirare cont"]
JOB_INVESTMENT_WORDS = ["job", "angajare", "lucru de acasa", "castig rapid", "investitie", "profit", "crypto", "bitcoin", "trading", "randament", "venit pasiv", "fara experienta", "bonus", "comision"]

CRYPTO_PLATFORM_WORDS = ["binance", "crypto.com", "crypto com", "coinbase", "kraken", "metamask", "trust wallet", "blockchain", "okx", "bybit", "kucoin"]
CRYPTO_SECURITY_WORDS = [
    "cont compromis",
    "acces neautorizat",
    "activitate suspecta",
    "login suspect",
    "conectare suspecta",
    "securitate cont",
    "verifica contul",
    "resetare parola",
    "autentificare",
    "confirmare cont",
    "cont blocat",
    "cont suspendat",
    "retragere suspecta",
    "tranzactie suspecta",
    "portofel compromis",
    "wallet compromis",
]

OTP_CODE_WORDS = ["cod", "otp", "cod verificare", "cod securitate", "cod autentificare", "pin", "parola", "sms code", "verificare cont", "autentificare", "confirma codul", "trimite codul"]
FRIEND_ACCOUNT_WORDS = ["sunt eu", "mi-am pierdut telefonul", "am alt numar", "whatsapp", "cont blocat", "ajuta-ma", "poti sa ma ajuti", "trimite-mi bani", "transfer rapid", "nu pot vorbi", "scrie-mi aici"]
CALL_BACK_WORDS = ["suna", "sunati", "apelati", "apel urgent", "numar", "deblocare", "verificare cont", "suport clienti", "operator", "departament securitate"]

OFFICIAL_DOMAINS_BY_BRAND = {
    "vodafone": ["vodafone.ro", "my.vodafone.ro"],
    "orange": ["orange.ro", "my.orange.ro"],
    "digi": ["digi.ro", "rcs-rds.ro"],
    "emag": ["emag.ro"],
    "lidl": ["lidl.ro"],
    "anaf": ["anaf.ro"],
    "fan courier": ["fancourier.ro"],
    "sameday": ["sameday.ro"],
    "cargus": ["cargus.ro"],
    "dhl": ["dhl.com", "dhl.ro"],
    "dpd": ["dpd.com", "dpd.ro"],
    "gls": ["gls-group.com", "gls-romania.ro"],
    "netflix": ["netflix.com"],
    "google": ["google.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "facebook": ["facebook.com"],
    "meta": ["meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "binance": ["binance.com"],
    "crypto.com": ["crypto.com"],
    "crypto com": ["crypto.com"],
    "coinbase": ["coinbase.com"],
    "kraken": ["kraken.com"],
    "metamask": ["metamask.io"],
    "trust wallet": ["trustwallet.com"],
    "blockchain": ["blockchain.com"],
    "okx": ["okx.com"],
    "bybit": ["bybit.com"],
    "kucoin": ["kucoin.com"],
}

SHORTENED_LINK_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "cutt.ly", "is.gd"]
SUSPICIOUS_TLDS = [".info", ".top", ".xyz", ".click", ".work", ".tk", ".ml"]


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text.strip().lower())
    without_diacritics = "".join(character for character in normalized if not unicodedata.combining(character))
    return re.sub(r"\s+", " ", without_diacritics)


def contains_any_keyword(text: str, keywords: list[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def contains_romanian_phone_number(text: str) -> bool:
    return re.search(r"(?<!\d)(?:\+4|004)?\s*07(?:[\s-]?\d){8}(?!\d)", text) is not None


def extract_domains(text: str) -> list[str]:
    domain_pattern = r"\b(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)\b"
    domains: list[str] = []

    for match in re.finditer(domain_pattern, text):
        raw_domain = match.group(0)
        parsed_domain = urlparse(raw_domain if "://" in raw_domain else f"http://{raw_domain}").netloc
        domain = parsed_domain.lower().removeprefix("www.")

        if domain and domain not in domains:
            domains.append(domain)

    return domains


def compact_text(value: str) -> str:
    return value.replace("-", "").replace(".", "").replace(" ", "")


def is_domain_official_for_brand(domain: str, brand: str) -> bool:
    official_domains = OFFICIAL_DOMAINS_BY_BRAND.get(brand, [])
    return any(domain == official_domain or domain.endswith(f".{official_domain}") for official_domain in official_domains)


def is_known_official_domain(domain: str) -> bool:
    return any(is_domain_official_for_brand(domain, brand) for brand in OFFICIAL_DOMAINS_BY_BRAND)


def domain_imitates_known_brand(domain: str) -> bool:
    compact_domain = compact_text(domain)

    for brand in OFFICIAL_DOMAINS_BY_BRAND:
        if compact_text(brand) in compact_domain and not is_domain_official_for_brand(domain, brand):
            return True

    return False


def domain_has_commercial_scam_terms(domain: str) -> bool:
    return contains_any_keyword(domain, COMMERCIAL_DOMAIN_WORDS)


def is_suspicious_domain(domain: str) -> bool:
    if is_known_official_domain(domain):
        return False

    return (
        domain in SHORTENED_LINK_DOMAINS
        or any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        or (
            domain.split(".")[0].count("-") >= 2
            and not domain_has_commercial_scam_terms(domain)
            and not domain_imitates_known_brand(domain)
        )
    )


def find_mentioned_brands(text: str) -> list[str]:
    return [brand for brand in OFFICIAL_DOMAINS_BY_BRAND if brand in text]


def find_mentioned_crypto_platforms(text: str) -> list[str]:
    return [platform for platform in CRYPTO_PLATFORM_WORDS if platform in text]


def has_unofficial_brand_domain(brand: str, domains: list[str]) -> bool:
    return any(not is_domain_official_for_brand(domain, brand) for domain in domains)


def analyze_phishing_text(text: str) -> list[str]:
    reasons: list[str] = []
    normalized_text = normalize_text(text)
    domains = extract_domains(normalized_text)
    mentioned_brands = find_mentioned_brands(normalized_text)
    mentioned_crypto_platforms = find_mentioned_crypto_platforms(normalized_text)

    has_domain = bool(domains)
    has_action = contains_any_keyword(normalized_text, ACTION_WORDS)
    has_urgency_or_threat = contains_any_keyword(normalized_text, URGENCY_THREAT_WORDS)
    has_payment_or_money = contains_any_keyword(normalized_text, PAYMENT_MONEY_WORDS)
    has_sensitive_data = contains_any_keyword(normalized_text, SENSITIVE_DATA_WORDS)
    has_phone_number = contains_romanian_phone_number(normalized_text)
    has_security_signal = has_sensitive_data or contains_any_keyword(normalized_text, BANKING_WORDS + CRYPTO_SECURITY_WORDS)

    if has_domain and any(is_suspicious_domain(domain) for domain in domains):
        add_reason(reasons, "Mesajul conține un link sau domeniu suspect.")

    if has_domain and any(domain_has_commercial_scam_terms(domain) for domain in domains):
        add_reason(reasons, "Domeniul conține termeni comerciali frecvent folosiți în campanii suspecte.")

    if has_domain and any(domain_imitates_known_brand(domain) for domain in domains):
        add_reason(reasons, "Domeniul pare să imite un brand cunoscut.")

    for brand in mentioned_brands:
        if has_unofficial_brand_domain(brand, domains):
            add_reason(reasons, "Mesajul menționează un brand cunoscut, dar linkul nu pare să fie domeniul oficial al brandului.")
            break

    if has_sensitive_data and has_action:
        add_reason(reasons, "Mesajul solicită date sensibile sau coduri de autentificare.")

    if has_urgency_or_threat:
        add_reason(reasons, "Mesajul folosește presiune, urgență sau amenințări pentru a grăbi decizia.")

    if has_phone_number:
        add_reason(reasons, "Mesajul conține un număr de telefon românesc. Verifică numărul dintr-o sursă oficială.")

    if contains_any_keyword(normalized_text, BANKING_WORDS) and (
        has_action or has_urgency_or_threat or (has_sensitive_data and (has_domain or has_payment_or_money))
    ):
        add_reason(reasons, "Mesajul seamănă cu o tentativă de phishing bancar.")

    if contains_any_keyword(normalized_text, DELIVERY_WORDS) and (has_action or has_payment_or_money or has_domain):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip livrare/colet fals.")

    if contains_any_keyword(normalized_text, PRIZE_WORDS) and has_action and has_domain:
        add_reason(reasons, "Mesajul combină promisiunea unui premiu cu un link de revendicare, semnal puternic de phishing.")

    if contains_any_keyword(normalized_text, PROMOTION_WORDS) and has_urgency_or_threat and has_domain:
        add_reason(reasons, "Mesajul folosește o ofertă promoțională urgentă și un link, semnal comun în scam-uri.")

    if contains_any_keyword(normalized_text, FAMILY_WORDS) and contains_any_keyword(normalized_text, EMERGENCY_ACCIDENT_WORDS):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip accident/rudă implicată într-o urgență.")

        if has_payment_or_money or has_action:
            add_reason(reasons, "Mesajul cere bani sau acțiune rapidă în contextul unei urgențe familiale.")

    has_invoice_or_bill = contains_any_keyword(normalized_text, INVOICE_PAYMENT_WORDS)
    has_service_or_provider = contains_any_keyword(normalized_text, SERVICE_ACCOUNT_WORDS) or contains_any_keyword(normalized_text, PROVIDER_WORDS)

    if has_invoice_or_bill and has_service_or_provider and (has_action or has_payment_or_money or has_domain or has_urgency_or_threat):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip factură neachitată/plată restantă falsă.")

        if has_action:
            add_reason(reasons, "Mesajul cere verificare sau plată rapidă, un semnal comun de phishing.")

    if contains_any_keyword(normalized_text, GOVERNMENT_WORDS) and (has_payment_or_money or has_action or has_urgency_or_threat):
        add_reason(reasons, "Mesajul poate imita o instituție publică pentru a cere plată sau date personale.")

    if contains_any_keyword(normalized_text, SUBSCRIPTION_WORDS) and (has_payment_or_money or has_action or has_urgency_or_threat):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip abonament sau cont fals.")

    if contains_any_keyword(normalized_text, JOB_INVESTMENT_WORDS) and (has_payment_or_money or has_action):
        add_reason(reasons, "Mesajul promite câștiguri rapide, un semnal comun în scam-uri financiare.")

    if mentioned_crypto_platforms and contains_any_keyword(normalized_text, CRYPTO_SECURITY_WORDS):
        add_reason(reasons, "Mesajul încearcă să imite o platformă crypto și sugerează o problemă de securitate.")

        if has_action or has_domain:
            add_reason(reasons, "Mesajul cere acțiune rapidă pentru accesarea sau securizarea contului crypto.")

    if contains_any_keyword(normalized_text, OTP_CODE_WORDS) and has_action:
        add_reason(reasons, "Mesajul încearcă să obțină un cod de verificare sau date de autentificare.")

    if contains_any_keyword(normalized_text, FRIEND_ACCOUNT_WORDS) and (has_payment_or_money or has_action):
        add_reason(reasons, "Mesajul poate proveni de la un cont compromis sau de la cineva care se dă drept o persoană cunoscută.")

    if contains_any_keyword(normalized_text, CALL_BACK_WORDS) and has_phone_number and (has_urgency_or_threat or has_security_signal):
        add_reason(reasons, "Mesajul cere apelarea unui număr pentru o problemă urgentă, posibilă tentativă de phishing telefonic.")

    return reasons
