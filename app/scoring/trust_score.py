from typing import Literal


RiskLevel = Literal["safe", "suspicious", "dangerous"]


REASON_WEIGHTS = {
    "Mesajul combină promisiunea unui premiu cu un link de revendicare, semnal puternic de phishing.": 30,
    "Mesajul folosește o ofertă promoțională urgentă și un link, semnal comun în scam-uri.": 25,
    "Domeniul conține termeni comerciali frecvent folosiți în campanii suspecte.": 20,
    "Mesajul conține un link sau domeniu suspect.": 25,
    "Mesajul menționează un brand cunoscut, dar linkul nu pare să fie domeniul oficial al brandului.": 15,
    "Domeniul pare să imite un brand cunoscut.": 15,
    "Mesajul solicită date sensibile sau coduri de autentificare.": 30,
    "Mesajul seamănă cu o tentativă de phishing bancar.": 25,
    "Mesajul seamănă cu o înșelătorie de tip livrare/colet fals.": 20,
    "Mesajul seamănă cu o înșelătorie de tip accident/rudă implicată într-o urgență.": 25,
    "Mesajul cere bani sau acțiune rapidă în contextul unei urgențe familiale.": 25,
    "Mesajul seamănă cu o înșelătorie de tip factură neachitată/plată restantă falsă.": 10,
    "Mesajul cere verificare sau plată rapidă, un semnal comun de phishing.": 10,
    "Mesajul poate imita o instituție publică pentru a cere plată sau date personale.": 25,
    "Mesajul seamănă cu o înșelătorie de tip abonament sau cont fals.": 20,
    "Mesajul promite câștiguri rapide, un semnal comun în scam-uri financiare.": 20,
    "Mesajul încearcă să imite o platformă crypto și sugerează o problemă de securitate.": 25,
    "Mesajul cere acțiune rapidă pentru accesarea sau securizarea contului crypto.": 20,
    "Mesajul încearcă să obțină un cod de verificare sau date de autentificare.": 30,
    "Mesajul poate proveni de la un cont compromis sau de la cineva care se dă drept o persoană cunoscută.": 25,
    "Mesajul cere apelarea unui număr pentru o problemă urgentă, posibilă tentativă de phishing telefonic.": 25,
    "Mesajul folosește presiune, urgență sau amenințări pentru a grăbi decizia.": 10,
    "Mesajul conține un număr de telefon românesc. Verifică numărul dintr-o sursă oficială.": 5,
}


def calculate_trust_score(reasons: list[str]) -> int:
    total_penalty = sum(REASON_WEIGHTS.get(reason, 15) for reason in reasons)
    return max(0, min(100, 100 - total_penalty))


def get_risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "safe"

    if score >= 45:
        return "suspicious"

    return "dangerous"


def get_recommendation(risk: RiskLevel) -> str:
    if risk == "safe":
        return "Mesajul nu pare periculos, dar verifică mereu sursa oficială."

    if risk == "suspicious":
        return "Mesajul are semnale suspecte. Nu accesa linkuri și verifică manual sursa."

    return "Mesajul pare periculos. Nu accesa linkuri, nu suna la numerele din mesaj și contactează instituția prin canalele oficiale."
