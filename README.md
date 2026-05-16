# Anti Scam Backend

A clean, beginner-friendly FastAPI MVP for detecting simple phishing signals in text messages.

## Project Structure

```text
anti-scam-backend/
  app/
    main.py
    api/
      phishing.py
    analyzers/
      phishing_analyzer.py
    scoring/
      trust_score.py
    core/
      config.py
  requirements.txt
  README.md
```

## 1. Create a Virtual Environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

## 2. Install Requirements

```bash
pip install -r requirements.txt
```

## 3. Run the Server

```bash
uvicorn app.main:app --reload
```

The API will run at:

```text
http://127.0.0.1:8000
```

## 4. Health Check

Open this URL in your browser:

```text
http://127.0.0.1:8000/
```

Expected response:

```json
{
  "status": "ok",
  "service": "anti-scam-backend"
}
```

## 5. Example Request

Send a POST request to:

```text
http://127.0.0.1:8000/analyze/phishing
```

Example body:

```json
{
  "text": "Urgent! Contul tau este suspendat. Verifica acum la https://example.com sau suna la 0712345678. Cod: 123456"
}
```

## 6. Example Response

```json
{
  "trust_score": 10,
  "risk": "dangerous",
  "reasons": [
    "Mesajul folosește cuvinte urgente care încearcă să te facă să acționezi rapid.",
    "Mesajul menționează informații bancare precum cont, bancă, card sau plată.",
    "Mesajul conține un link. Linkurile din mesaje necunoscute pot duce către site-uri false.",
    "Mesajul conține un număr de telefon românesc. Verifică numărul dintr-o sursă oficială.",
    "Mesajul conține un cod numeric de 4-6 cifre, posibil folosit pentru verificări false.",
    "Mesajul folosește expresii suspecte precum blocare cont, suspendat sau verificare."
  ],
  "recommendation": "Mesajul pare periculos. Nu accesa linkuri, nu suna la numerele din mesaj și contactează instituția prin canale oficiale."
}
```

## How It Works

The API receives text from the client, searches for simple phishing warning signs, calculates a trust score, then returns a risk level and recommendation.

This MVP does not use a database, Docker, Redis, Celery, external APIs, or OpenAI. Everything runs locally with straightforward Python code.
