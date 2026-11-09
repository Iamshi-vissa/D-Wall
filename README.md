# <img src="docs/headers/h1-x-wall.svg" alt="X-WALL" height="60">

Check a QR code or payment link for signs of a scam before you pay.

## <img src="docs/headers/h2-about.svg" alt="ABOUT" height="38">

Payment scams in India often arrive as a QR code or a *UPI* link: "scan to get your refund",
"claim your cashback". X-WALL takes the QR image or the link, works out where it really leads, and
gives it a score from 0 to 100 with a plain list of reasons, so you can decide before you pay.

It's a *prototype*. Some checks are real and some are still *placeholders* (see Status).

## <img src="docs/headers/h2-features.svg" alt="FEATURES" height="38">

- Upload a QR code image or paste a link or *UPI* string
- Follows redirects (up to 5 hops) and shows the full chain, so short links can't hide where they go
- Checks UPI payment requests: the payee ID format and the amount asked for
- Spots domains that look like payment brands (for example `paytrn` instead of `paytm`)
- Flags warning words like "refund", "KYC", "reward" or "suspended", plain HTTP, raw IP addresses
  and long chains of subdomains
- Optionally opens the page in a *headless browser* to look for password or card forms
- Result: **Safe** (0–30), **Suspicious** (31–70) or **Dangerous** (71–100), with the reasons

## <img src="docs/headers/h2-how-it-works.svg" alt="HOW IT WORKS" height="38">

1. The QR image is decoded with OpenCV and pyzbar to get the text inside it.
2. If it's a *UPI* string (`upi://pay?...`), the payee and amount are checked.
3. If it's a web link, the redirects are followed to the final address, and that address is checked
   against the rules above.
4. Each rule that matches adds points and a reason. The total becomes the *verdict*.

## <img src="docs/headers/h2-architecture.svg" alt="ARCHITECTURE" height="38">

```mermaid
flowchart TB
    IN[QR image or link] --> API[FastAPI]
    API --> D[Decode QR with pyzbar or OpenCV]
    D --> T{UPI or web link?}
    T -- UPI --> U[Check payee and amount]
    T -- link --> R[Follow redirects]
    R --> C[Rule checks: brands, keywords, HTTPS, IP, subdomains]
    C --> PW[Optional page check with Playwright]
    U --> S[Score 0 to 100 and verdict]
    PW --> S
    S --> APP[React app]
```

Each rule that matches adds points and a reason. The total decides the *verdict*.

## <img src="docs/headers/h2-tech-stack.svg" alt="TECH STACK" height="38">

<p align="center">
  <img src="https://img.shields.io/badge/Python-000000?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-000000?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/OpenCV-000000?style=flat-square&logo=opencv&logoColor=white" alt="OpenCV">
  <img src="https://img.shields.io/badge/React-000000?style=flat-square&logo=react&logoColor=white" alt="React">
  <img src="https://img.shields.io/badge/Vite-000000?style=flat-square&logo=vite&logoColor=white" alt="Vite">
  <img src="https://img.shields.io/badge/Playwright-000000?style=flat-square" alt="Playwright">
</p>

| Layer | Technology |
|---|---|
| API | Python, FastAPI |
| QR decoding | OpenCV, pyzbar |
| Link checks | requests; Playwright (optional) |
| Web app | React, Vite |

## <img src="docs/headers/h2-getting-started.svg" alt="GETTING STARTED" height="38">

You need Python 3.10+ and Node.js 20+. QR decoding with pyzbar also needs the zbar library
(`sudo apt install libzbar0` on Debian/Ubuntu, `brew install zbar` on macOS). Without it, X-WALL
falls back to OpenCV.

Backend:

```bash
git clone https://github.com/Iamshi-vissa/D-Wall.git
cd D-Wall/backend
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Optional, for the page check:

```bash
pip install playwright
playwright install chromium
```

Frontend, in a second terminal:

```bash
cd D-Wall/frontend
npm install
npm run dev
```

Open the address Vite prints, usually <http://localhost:5173>.

## <img src="docs/headers/h2-api.svg" alt="API" height="38">

| Endpoint | What it does |
|---|---|
| `GET /health` | Check the API is running |
| `POST /analyze/link` | Body `{"input": "<link or UPI string>"}` |
| `POST /analyze/qr` | Upload a QR image as `file` |

## <img src="docs/headers/h2-project-structure.svg" alt="PROJECT STRUCTURE" height="38">

```
backend/main.py     the API and every check
frontend/src/       the web app that runs today
frontend/client/    a newer interface, not wired up yet (see Status)
```

## <img src="docs/headers/h2-status.svg" alt="STATUS" height="38">

*Prototype*. Things that need work:

- **Domain age is fake.** It's a made-up number based on the domain's letters, and it still adds
  points to the score. It should either use a real WHOIS lookup or be switched off.
- **Threat lists aren't checked.** The lookup always says "not listed". It should call a service
  like Google Safe Browsing, VirusTotal or PhishTank.
- **Two frontends.** `npm run dev` serves the original interface in `frontend/src`. The newer one in
  `frontend/client` is more complete, but it doesn't build yet: it still depends on packages from the
  tool it was made with, which aren't in the lockfile.
- The brand list only covers Indian payment apps (Paytm, PhonePe, Google Pay, BHIM and others).
- There are no automated tests yet.

## <img src="docs/headers/h2-license.svg" alt="LICENSE" height="38">

MIT. See [LICENSE](LICENSE).
