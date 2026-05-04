import re
import unicodedata
from urllib.parse import urlparse


# Common signals reused by multiple scam categories.
# Keeping these lists grouped makes the rules easy to read and adjust later.
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
    "reseteaza",
    "resetati",
    "securizeaza",
    "securizati",
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
    "astazi",
    "termen limita",
    "rapid",
    "repede",
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


# Official domains for known brands/providers.
# A brand name by itself is not suspicious; the domain must be unofficial or the text
# must include another risky action such as payment, urgency, or sensitive data.
OFFICIAL_DOMAINS_BY_BRAND = {
    "vodafone": ["vodafone.ro", "my.vodafone.ro"],
    "orange": ["orange.ro", "my.orange.ro"],
    "digi": ["digi.ro", "rcs-rds.ro"],
    "emag": ["emag.ro"],
    "lidl": ["lidl.ro"],
    "kaufland": ["kaufland.ro"],
    "carrefour": ["carrefour.ro"],
    "altex": ["altex.ro"],
    "flanco": ["flanco.ro"],
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
    "trustwallet": ["trustwallet.com"],
    "blockchain": ["blockchain.com"],
    "blockchain.com": ["blockchain.com"],
    "okx": ["okx.com"],
    "bybit": ["bybit.com"],
    "kucoin": ["kucoin.com"],
}

SHORTENED_LINK_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "cutt.ly", "is.gd"]


# Scam category keywords.
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
    "ron",
    "lei",
    "euro",
    "dolari",
]

# Accident scams often pretend that a family member is in danger.
FAMILY_WORDS = ["fiu", "fiica", "copil", "mama", "tata", "sot", "sotie", "frate", "sora", "bunic", "bunica", "nepot", "nepoata", "ruda"]
EMERGENCY_ACCIDENT_WORDS = ["accident", "spital", "urgenta", "ambulanta", "politie", "avocat", "operatie", "interventie", "ranit", "arestat", "problema grava"]

INVOICE_PAYMENT_WORDS = ["factura", "neachitata", "neachitat", "plata restanta", "sold restant", "restanta", "datorie", "suma datorata", "achitare", "achita", "plateste", "platiti", "plata"]
SERVICE_ACCOUNT_WORDS = ["serviciu", "cont", "abonament", "suspendat", "suspendare", "dezactivat", "dezactivare", "blocat", "restrictionat"]
PROVIDER_WORDS = ["orange", "vodafone", "digi", "telekom", "enel", "eon", "hidroelectrica", "electrica", "engie"]

GOVERNMENT_WORDS = ["anaf", "taxe", "impozit", "datorie", "amenda", "poprire", "declaratie", "verificare fiscala", "plata restanta", "guvern", "politie", "judecatorie", "dosar", "sanctiune"]

SUBSCRIPTION_WORDS = ["netflix", "spotify", "youtube", "google", "apple", "microsoft", "meta", "facebook", "instagram", "abonament", "cont suspendat", "plata esuata", "actualizeaza plata", "metoda de plata", "expirare cont"]

JOB_INVESTMENT_WORDS = ["job", "angajare", "lucru de acasa", "castig rapid", "investitie", "profit", "crypto", "bitcoin", "trading", "randament", "venit pasiv", "fara experienta", "bonus", "comision"]

SENSITIVE_DATA_WORDS = ["cnp", "cvv", "pin", "parola", "iban", "card", "date card", "cod", "otp", "cod verificare", "cod securitate", "cod autentificare", "date personale", "datele tale", "numar card", "expirare card"]
OTP_CODE_WORDS = ["cod", "otp", "cod verificare", "cod securitate", "cod autentificare", "pin", "parola", "sms code", "verificare cont", "autentificare", "confirma codul", "trimite codul"]

FRIEND_ACCOUNT_WORDS = ["sunt eu", "mi-am pierdut telefonul", "am alt numar", "whatsapp", "cont blocat", "ajuta-ma", "poti sa ma ajuti", "trimite-mi bani", "transfer rapid", "nu pot vorbi", "scrie-mi aici"]

CALL_BACK_WORDS = ["suna", "sunati", "apelati", "apel urgent", "numar", "deblocare", "verificare cont", "suport clienti", "operator", "departament securitate"]

# Crypto platform impersonation scams often pretend that an account or wallet
# was compromised, then push the user to click a fake security link.
CRYPTO_PLATFORM_WORDS = [
    "binance",
    "crypto.com",
    "crypto com",
    "coinbase",
    "kraken",
    "metamask",
    "trust wallet",
    "blockchain",
    "blockchain.com",
    "okx",
    "bybit",
    "kucoin",
]

CRYPTO_SECURITY_WORDS = [
    "cont compromis",
    "contul tau a fost compromis",
    "acces neautorizat",
    "activitate suspecta",
    "login suspect",
    "conectare suspecta",
    "securitate cont",
    "verifica contul",
    "verificati contul",
    "resetare parola",
    "reseteaza parola",
    "autentificare",
    "confirmare cont",
    "cont blocat",
    "cont suspendat",
    "retragere suspecta",
    "tranzactie suspecta",
    "portofel compromis",
    "wallet compromis",
]

CRYPTO_BENIGN_STATUS_PHRASES = [
    "autentificare reusita",
    "extrasul lunar este disponibil",
    "tranzactia ta a fost finalizata",
]

CRYPTO_ACTION_WORDS = [
    "acceseaza",
    "accesati",
    "intra",
    "intrati",
    "confirma",
    "confirmati",
    "verifica",
    "verificati",
    "reseteaza",
    "resetati",
    "securizeaza",
    "securizati",
]


# We normalize text by lowercasing and removing Romanian diacritics.
# This helps "plătește" match the keyword "plateste".
def normalize_text(text: str) -> str:
    lowercase_text = text.lower()
    without_diacritics = unicodedata.normalize("NFKD", lowercase_text)
    return "".join(character for character in without_diacritics if not unicodedata.combining(character))


# This helper checks whether any keyword from a list exists in the message.
def contains_any_keyword(text: str, keywords: list[str]) -> bool:
    return any(keyword in text for keyword in keywords)


# This helper adds each reason only once, even if multiple rules find the same issue.
def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


# This regex detects Romanian mobile numbers in common SMS formats:
# 07xxxxxxxx, +407xxxxxxxx, 00407xxxxxxxx, with optional spaces or dashes.
def contains_romanian_phone_number(text: str) -> bool:
    return re.search(r"(?<!\d)(?:\+4|004)?\s*07(?:[\s-]?\d){8}(?!\d)", text) is not None


# This function extracts domains from links or plain domains in an SMS.
# It detects http://example.com, https://example.com, www.example.com, and example.ro.
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


# Official domains can also have subdomains, such as login.google.com.
def is_domain_official_for_brand(domain: str, brand: str) -> bool:
    official_domains = OFFICIAL_DOMAINS_BY_BRAND.get(brand, [])
    return any(domain == official_domain or domain.endswith(f".{official_domain}") for official_domain in official_domains)


def is_known_official_domain(domain: str) -> bool:
    return any(is_domain_official_for_brand(domain, brand) for brand in OFFICIAL_DOMAINS_BY_BRAND)


def compact_brand_text(value: str) -> str:
    return value.replace("-", "").replace(".", "").replace(" ", "")


# A fake domain may include a brand name while not being the official domain.
# Example: vodafone-plata-rapid.com contains "vodafone" but is not vodafone.ro.
def domain_imitates_known_brand(domain: str) -> bool:
    compact_domain = compact_brand_text(domain)

    for brand in OFFICIAL_DOMAINS_BY_BRAND:
        compact_brand = compact_brand_text(brand)
        if compact_brand in compact_domain and not is_domain_official_for_brand(domain, brand):
            return True

    return False


def domain_imitates_crypto_platform(domain: str) -> bool:
    compact_domain = compact_brand_text(domain)

    for platform in CRYPTO_PLATFORM_WORDS:
        compact_platform = compact_brand_text(platform)
        if compact_platform in compact_domain and not is_domain_official_for_brand(domain, platform):
            return True

    return False


def domain_has_many_hyphens(domain: str) -> bool:
    domain_name = domain.split(".")[0]
    return domain_name.count("-") >= 2


def is_shortened_link(domain: str) -> bool:
    return domain in SHORTENED_LINK_DOMAINS


def find_mentioned_brands(text: str) -> list[str]:
    return [brand for brand in OFFICIAL_DOMAINS_BY_BRAND if brand in text]


def find_mentioned_crypto_platforms(text: str) -> list[str]:
    return [platform for platform in CRYPTO_PLATFORM_WORDS if platform in text]


# This function analyzes a message and returns human-readable warning signs.
# It does not calculate the final score; it only explains what looked suspicious.
def analyze_phishing_text(text: str) -> list[str]:
    reasons: list[str] = []
    normalized_text = normalize_text(text)
    domains = extract_domains(normalized_text)
    mentioned_brands = find_mentioned_brands(normalized_text)
    mentioned_crypto_platforms = find_mentioned_crypto_platforms(normalized_text)

    has_domain = len(domains) > 0
    has_action = contains_any_keyword(normalized_text, ACTION_WORDS)
    has_crypto_action = contains_any_keyword(normalized_text, CRYPTO_ACTION_WORDS)
    has_urgency_or_threat = contains_any_keyword(normalized_text, URGENCY_THREAT_WORDS)
    has_payment_or_money = contains_any_keyword(normalized_text, PAYMENT_MONEY_WORDS)
    has_phone_number = contains_romanian_phone_number(normalized_text)
    has_sensitive_data = contains_any_keyword(normalized_text, SENSITIVE_DATA_WORDS)
    has_crypto_security_problem = contains_any_keyword(normalized_text, CRYPTO_SECURITY_WORDS) and not contains_any_keyword(normalized_text, CRYPTO_BENIGN_STATUS_PHRASES)
    has_job_investment_signal = contains_any_keyword(normalized_text, JOB_INVESTMENT_WORDS) and not mentioned_crypto_platforms

    # Links are risky when they are not known official domains, are shortened,
    # contain many hyphens, or imitate a known brand.
    suspicious_domains = [
        domain
        for domain in domains
        if not is_known_official_domain(domain)
        or is_shortened_link(domain)
        or domain_has_many_hyphens(domain)
        or domain_imitates_known_brand(domain)
    ]

    if suspicious_domains:
        add_reason(reasons, "Mesajul conține un link sau domeniu suspect.")

    if any(domain_imitates_known_brand(domain) for domain in domains):
        add_reason(reasons, "Domeniul pare să imite un brand cunoscut.")

    if any(domain_imitates_crypto_platform(domain) for domain in domains):
        add_reason(reasons, "Domeniul pare să imite o platformă crypto cunoscută.")

    # A known brand plus an unofficial domain is a stronger sign of impersonation.
    for brand in mentioned_brands:
        if any(not is_domain_official_for_brand(domain, brand) for domain in domains):
            add_reason(reasons, "Mesajul menționează un brand cunoscut, dar linkul nu pare să fie domeniul oficial al brandului.")
            break

    # Crypto platform names are safe by themselves. They become suspicious when
    # paired with a fake domain or account-security warning.
    for platform in mentioned_crypto_platforms:
        if any(not is_domain_official_for_brand(domain, platform) for domain in domains):
            add_reason(reasons, "Domeniul nu pare să fie site-ul oficial al platformei crypto menționate.")
            break

    if has_sensitive_data and has_action:
        add_reason(reasons, "Mesajul solicită date sensibile sau coduri de autentificare.")

    # Urgency alone is a weak signal, but still useful because many scams create pressure.
    if has_urgency_or_threat:
        add_reason(reasons, "Mesajul folosește presiune, urgență sau amenințări pentru a grăbi decizia.")

    if has_phone_number:
        add_reason(reasons, "Mesajul conține un număr de telefon românesc. Verifică numărul dintr-o sursă oficială.")

    # Numeric codes alone are not always phishing, but they deserve caution.
    if re.search(r"\b\d{4,6}\b", normalized_text):
        add_reason(reasons, "Mesajul conține un cod numeric de 4-6 cifre, posibil folosit pentru verificări false.")

    # 1. Fake bank/account security.
    if contains_any_keyword(normalized_text, BANKING_WORDS) and (has_action or has_urgency_or_threat):
        add_reason(reasons, "Mesajul seamănă cu o tentativă de phishing bancar.")

    # 2. Fake courier/delivery.
    if contains_any_keyword(normalized_text, DELIVERY_WORDS) and (has_action or has_payment_or_money or has_domain):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip livrare/colet fals.")

    # 3. Fake prize/voucher/lottery.
    if contains_any_keyword(normalized_text, PRIZE_WORDS) and has_action:
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip premiu/voucher fals.")

        if mentioned_brands:
            add_reason(reasons, "Mesajul folosește numele unui brand cunoscut pentru a părea credibil.")

    # 4. Accident/family emergency.
    if contains_any_keyword(normalized_text, FAMILY_WORDS) and contains_any_keyword(normalized_text, EMERGENCY_ACCIDENT_WORDS):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip accident/rudă implicată într-o urgență.")

        if has_payment_or_money or has_action:
            add_reason(reasons, "Mesajul cere bani sau acțiune rapidă în contextul unei urgențe familiale.")

    # 5. Fake unpaid invoice/bill.
    if contains_any_keyword(normalized_text, INVOICE_PAYMENT_WORDS) and contains_any_keyword(normalized_text, SERVICE_ACCOUNT_WORDS):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip factură neachitată/plată restantă falsă.")

        if has_action:
            add_reason(reasons, "Mesajul cere verificare sau plată rapidă, un semnal comun de phishing.")

        if contains_any_keyword(normalized_text, PROVIDER_WORDS):
            add_reason(reasons, "Mesajul folosește numele unui furnizor real pentru a părea credibil.")

    # 6. Fake ANAF/government.
    if contains_any_keyword(normalized_text, GOVERNMENT_WORDS) and (has_payment_or_money or has_action or has_urgency_or_threat):
        add_reason(reasons, "Mesajul poate imita o instituție publică pentru a cere plată sau date personale.")

    # 7. Fake subscription/account renewal.
    if contains_any_keyword(normalized_text, SUBSCRIPTION_WORDS) and (has_payment_or_money or has_action or has_urgency_or_threat):
        add_reason(reasons, "Mesajul seamănă cu o înșelătorie de tip abonament sau cont fals.")

    # 8. Job/investment/crypto.
    if has_job_investment_signal and (has_payment_or_money or has_action):
        add_reason(reasons, "Mesajul promite câștiguri rapide, un semnal comun în scam-uri financiare.")

    # 9. Fake OTP/verification code.
    if contains_any_keyword(normalized_text, OTP_CODE_WORDS) and has_action:
        add_reason(reasons, "Mesajul încearcă să obțină un cod de verificare sau date de autentificare.")

    # 10. Compromised WhatsApp/friend account.
    if contains_any_keyword(normalized_text, FRIEND_ACCOUNT_WORDS) and (has_payment_or_money or has_action):
        add_reason(reasons, "Mesajul poate proveni de la un cont compromis sau de la cineva care se dă drept o persoană cunoscută.")

    # 11. Call-back scam.
    if contains_any_keyword(normalized_text, CALL_BACK_WORDS) and has_phone_number and (has_urgency_or_threat or has_sensitive_data):
        add_reason(reasons, "Mesajul cere apelarea unui număr pentru o problemă urgentă, posibilă tentativă de phishing telefonic.")

    # 12. Crypto platform impersonation / compromised account scam.
    # These messages pretend to be Binance, Coinbase, MetaMask, Trust Wallet, etc.
    # They usually claim there is a security problem, then ask the user to click a
    # fake link or take quick action to "secure" the account.
    if mentioned_crypto_platforms and has_crypto_security_problem:
        add_reason(reasons, "Mesajul încearcă să imite o platformă crypto și sugerează o problemă de securitate.")

        if has_crypto_action or has_domain:
            add_reason(reasons, "Mesajul cere acțiune rapidă pentru accesarea sau securizarea contului crypto.")

    return reasons
