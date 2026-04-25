from typing import Literal


RiskLevel = Literal["safe", "suspicious", "dangerous"]


# Weighted scoring makes severe signals reduce trust more than weak signals.
# The API response stays the same: only the final score, risk, reasons, and recommendation are returned.
REASON_WEIGHTS = {
    "Mesajul conține un link sau domeniu suspect.": 25,
    "Mesajul menționează un brand cunoscut, dar linkul nu pare să fie domeniul oficial al brandului.": 30,
    "Domeniul pare să imite un brand cunoscut.": 30,
    "Mesajul solicită date sensibile sau coduri de autentificare.": 30,
    "Mesajul seamănă cu o tentativă de phishing bancar.": 25,
    "Mesajul seamănă cu o înșelătorie de tip livrare/colet fals.": 20,
    "Mesajul seamănă cu o înșelătorie de tip premiu/voucher fals.": 20,
    "Mesajul folosește numele unui brand cunoscut pentru a părea credibil.": 15,
    "Mesajul seamănă cu o înșelătorie de tip accident/rudă implicată într-o urgență.": 25,
    "Mesajul cere bani sau acțiune rapidă în contextul unei urgențe familiale.": 20,
    "Mesajul seamănă cu o înșelătorie de tip factură neachitată/plată restantă falsă.": 25,
    "Mesajul cere verificare sau plată rapidă, un semnal comun de phishing.": 15,
    "Mesajul folosește numele unui furnizor real pentru a părea credibil.": 10,
    "Mesajul poate imita o instituție publică pentru a cere plată sau date personale.": 25,
    "Mesajul seamănă cu o înșelătorie de tip abonament sau cont fals.": 20,
    "Mesajul promite câștiguri rapide, un semnal comun în scam-uri financiare.": 20,
    "Mesajul încearcă să obțină un cod de verificare sau date de autentificare.": 30,
    "Mesajul poate proveni de la un cont compromis sau de la cineva care se dă drept o persoană cunoscută.": 25,
    "Mesajul cere apelarea unui număr pentru o problemă urgentă, posibilă tentativă de phishing telefonic.": 25,
    "Mesajul folosește presiune, urgență sau amenințări pentru a grăbi decizia.": 10,
    "Mesajul conține un număr de telefon românesc. Verifică numărul dintr-o sursă oficială.": 5,
    "Mesajul conține un cod numeric de 4-6 cifre, posibil folosit pentru verificări false.": 5,
}


# This function converts detected warning signs into a trust score.
# We start from 100 because a message is considered safe until rules find problems.
def calculate_trust_score(reasons: list[str]) -> int:
    starting_score = 100

    # Each reason has its own weight.
    # Unknown future reasons default to 15 so they still affect the score.
    total_penalty = sum(REASON_WEIGHTS.get(reason, 15) for reason in reasons)
    score = starting_score - total_penalty

    # Clamp the score between 0 and 100 so the API always returns a valid value.
    return max(0, min(100, score))


# This function translates the numeric score into a simple risk label.
def get_risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "safe"

    if score >= 45:
        return "suspicious"

    return "dangerous"


# This function gives the user practical advice based on the risk level.
def get_recommendation(risk: RiskLevel) -> str:
    if risk == "safe":
        return "Mesajul nu pare periculos, dar verifică mereu sursa oficială."

    if risk == "suspicious":
        return "Mesajul are semnale suspecte. Nu accesa linkuri și verifică manual sursa."

    return "Mesajul pare periculos. Nu accesa linkuri, nu suna la numerele din mesaj și contactează instituția prin canalele oficiale."
