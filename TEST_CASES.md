# Manual Test Cases

These test cases help verify SignalCheck's rule-based behavior without using real malicious content.

## Test 1 — Legitimate Message

**Goal:** confirm that a normal message with passing authentication remains low risk.

Expected:
- Low Risk
- No credential-request finding
- No suspicious attachment finding

## Test 2 — Password + MFA Request

**Goal:** verify strong credential-harvesting indicators.

Expected findings:
- Password request
- MFA / verification code request
- Credential-harvesting language

Expected band:
- High Risk

## Test 3 — Reply-To Mismatch

**Goal:** verify sender / reply-domain mismatch handling.

Expected finding:
- Sender and Reply-To domains differ

## Test 4 — Executable Attachment

Example filename:

```text
Invoice_2841.pdf.exe
```

Expected findings:
- Unusual attachment filename
- Executable or script attachment
- Invoice or payment language

## Test 5 — Authentication Failure

Include a fictional header such as:

```text
Authentication-Results: mx.example.test; spf=fail; dkim=fail; dmarc=fail
```

Expected findings:
- SPF authentication failure
- DKIM authentication failure
- DMARC authentication failure

## Test 6 — Shortened / Raw-IP URL

Use only safe fictional text or reserved examples. Do not visit links.

Expected:
- appropriate URL-related warning when the input matches a supported pattern

## Notes

The goal of these checks is to verify consistent rule behavior, not to prove that a message is malicious or safe.
