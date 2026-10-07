# 🎣 Phishing Email Analyser (SignalCheck)

SignalCheck is a small educational email-triage tool built with plain HTML, CSS, and JavaScript.

Paste an email into the browser and the tool produces a transparent 0–100 warning score based on suspicious indicators such as credential requests, Reply-To mismatches, authentication failures, risky links, and dangerous attachment names.

> SignalCheck is a rule-based learning project. It is not an email gateway, malware scanner, calibrated probability model, or replacement for professional phishing analysis.

## 🎯 Portfolio Goals

This project demonstrates:

- phishing indicator analysis
- explainable risk scoring
- basic email-header inspection
- safe browser-side processing
- JavaScript logic and UI development
- security-focused documentation

## ✨ What It Checks

SignalCheck looks for indicators including:

- urgency and pressure
- account suspension or closure threats
- password requests
- MFA / verification-code requests
- payment, wire, and gift-card requests
- changed bank details
- suspicious or unusual URLs
- shortened URLs
- URLs using raw IP addresses
- mismatched link text and destination
- brand / authority impersonation language
- unusual or executable attachments
- requests to enable macros
- invoice / BEC-style language
- credential-harvesting language
- mismatched From and Reply-To domains
- SPF, DKIM, and DMARC failures when pasted in Authentication-Results

## 🚀 Run It

No installation is required.

```text
1. Clone or download the repository
2. Open index.html in a modern browser
3. Paste a test email
4. Select Analyse
```

There is no backend, database, account, API key, analytics service, or external AI API.

## 🔐 Privacy

All analysis happens locally in `app.js` inside the visitor's browser.

The application does not:

- upload email text
- save pasted messages
- make network requests
- call external APIs
- use analytics or tracking

Do not paste sensitive email into a site unless you trust how that site is hosted.

## 🧮 How the Score Works

Each detected indicator contributes a fixed number of points. The total is capped at 100.

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
| Mismatched link text and destination | 14 |
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

Risk bands:

- **Low Risk:** 0–24
- **Suspicious:** 25–59
- **High Risk:** 60–100

The score is an explainable checklist, not a probability that an email is malicious.

## 🧪 Test Scenarios

The interface includes fictional samples covering:

- obvious credential phishing
- a more convincing re-authentication phish
- fake Microsoft 365 alerts
- parcel-delivery scams
- invoice / BEC-style requests
- a legitimate comparison example

The samples use reserved `.invalid` or `.test` domains where applicable.

See [TEST_CASES.md](TEST_CASES.md) for a simple manual testing checklist.

## 📁 Project Structure

```text
phishing-email-analyser/
├── index.html
├── app.js
├── styles.css
├── TEST_CASES.md
└── README.md
```

## ⚠️ Limitations

- Rule-based patterns can miss new or unusual phishing techniques.
- Legitimate emails may contain language that triggers warnings.
- Pasted headers may be incomplete or forged.
- The tool does not resolve redirects or visit URLs.
- It does not scan attachments or perform malware analysis.
- A low score does not prove an email is safe.
- A high score does not prove an email is malicious.

## 🛡️ Safe Use

Never click a suspicious link or open an attachment just to test it.

For important requests, independently verify the sender using an official website, application, phone number, or known contact channel.

## 🔭 Roadmap

- [ ] Add screenshots to the README
- [ ] Publish a safe live demo with GitHub Pages
- [ ] Add automated rule tests
- [ ] Improve parsing of email headers
- [ ] Add clearer evidence output for each finding
- [ ] Add exportable triage summaries
