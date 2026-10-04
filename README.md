# Phishing Email Analyser (SignalCheck)

A small educational email triage tool built with plain HTML, CSS, and JavaScript. Paste an email to see a 0–100 warning score, the signals that contributed to it, and safer next steps.

## Run it

Open `index.html` in a modern web browser. There is no install step, backend, account, database, or API key. The same files can be hosted as a static website, including with GitHub Pages.

## Privacy

All analysis happens in `app.js` inside the visitor's browser. The app does not upload or save pasted email text, make network requests, call AI or other APIs, or use analytics and tracking. It uses system fonts and has no third-party dependencies. Do not paste sensitive email into a website unless you trust how that site is hosted and served.

## How the score works

The score adds the fixed points for each detected indicator, then caps the result at 100. A pattern is counted once per indicator, even if it appears many times.

| Indicator | Points |
| --- | ---: |
| Urgency and pressure | 10 |
| Account suspension or closure threat | 18 |
| Password request | 25 |
| MFA or verification code request | 22 |
| Payment, wire, or gift-card request | 18 |
| Bank-detail change request | 25 |
| Unusual URL pattern | 20 |
| Shortened URL | 15 |
| URL using a raw IP address | 25 |
| Mismatched link text and destination (when detectable) | 14 |
| Brand or authority impersonation language | 8 |
| Unusual attachment filename | 15 |
| Executable or script attachment | 25 |
| Request to enable macros | 18 |
| Invoice or payment language | 12 |
| Credential-harvesting language | 20 |
| From and Reply-To domains differ | 15 |
| SPF failure in pasted authentication headers | 15 |
| DKIM failure in pasted authentication headers | 12 |
| DMARC failure in pasted authentication headers | 15 |

Risk bands: **Low Risk** (0–24), **Suspicious** (25–59), and **High Risk** (60–100). This is a transparent checklist, not a calibrated probability or a verdict. Email text can be incomplete or forged, and new scams may not match these rules.

## Safe use

This is an educational triage tool. A low score does not prove a message is safe, and a high score does not prove it is malicious. Never click a suspicious link or open an attachment to test it. Verify important requests with an organisation through its official website, app, or contact information you already know.

The sample messages are fictional and use reserved `.invalid` or `.test` domains so their links cannot lead to real services.
