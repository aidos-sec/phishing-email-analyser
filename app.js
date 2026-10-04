// SignalCheck performs every check on the visitor's device. No network calls or telemetry.
const samples = [
  { name: 'Obvious phishing', level: 'HIGH', text: `From: Security Desk <alerts@company-example.invalid>\nReply-To: verify-now@outside-example.invalid\nSubject: URGENT: account closure today\n\nYour account will be permanently suspended in 30 minutes. Confirm your password and MFA verification code now at https://company-login.example.invalid/verify or lose access. Failure to act will result in account closure.` },
  { name: 'Sophisticated phish', level: 'HIGH', text: `From: Elena Park <elena.park@northstar-example.invalid>\nReply-To: elena.park@secure-mail.example.invalid\nSubject: Updated access review before 3pm\n\nHi, following the quarterly access review, please re-authenticate your Microsoft 365 account before the 3pm cutoff so Finance can release the shared report. I have pre-filled the secure sign-in page here: https://m365-review.example.invalid/session. Please reply with the six-digit verification code if the page asks for it. Thanks, Elena` },
  { name: 'Fake Microsoft 365', level: 'HIGH', text: `From: Microsoft 365 <notifications@microsoft-alerts.example.invalid>\nReply-To: case-472@outside-example.invalid\nSubject: Mailbox storage and sign-in warning\n\nWe detected unusual activity. Your mailbox will be closed today unless you verify your password and MFA code at https://office-check.example.invalid. Do not ignore this important security notice.` },
  { name: 'Fake parcel delivery', level: 'SUSPICIOUS', text: `From: Parcel Updates <delivery@parcel-example.invalid>\nSubject: Delivery attempt failed\n\nWe could not deliver your parcel because a small address fee is due. Pay the fee today to reschedule: https://track-parcel.example.invalid/fee. If you do not act, your parcel will be returned.` },
  { name: 'Fake invoice / BEC', level: 'HIGH', text: `From: Jordan Lee <jordan@vendor-example.invalid>\nReply-To: jordan-payments@outside-example.invalid\nSubject: Updated bank details — invoice 2841\n\nPlease process the attached invoice today using our new bank details below. This change is confidential and must be completed before close of business. Reply when the wire transfer is sent. Attachment: Invoice_2841.pdf.exe` },
  { name: 'Legitimate example', level: 'LOW', text: `From: Maya Chen <maya@community-example.test>\nReply-To: maya@community-example.test\nSubject: Notes from Saturday's book club\n\nHi everyone, thanks for joining the discussion. Our next meeting is Saturday at 10:30 in the library room. I have attached the reading list as reading-list.pdf. There is no action needed before then. See you soon, Maya\n\nAuthentication-Results: mx.community-example.test; spf=pass; dkim=pass; dmarc=pass` }
];
const weights = {
  urgency: 10, threat: 18, password: 25, mfa: 22, payment: 18, bank: 25,
  suspiciousUrl: 20, shortened: 15, rawIp: 25, misleading: 14, impersonation: 8,
  attachment: 15, executable: 25, macros: 18, invoice: 12, credential: 20,
  replyMismatch: 15, spf: 15, dkim: 12, dmarc: 15
};
const rules = [
  ['urgency','Urgency and pressure','The message uses deadlines or pressure to rush a decision. Attackers often try to stop people from checking first.',/\b(urgent|immediately|act now|within \d+ (minutes?|hours?)|right away|before (close of business|\d)|limited time|final notice|do not delay)\b/i],
  ['threat','Account suspension or closure threat','It threatens suspension, closure, deletion, or loss of access to push you into acting.',/\b(account|mailbox|access|service).{0,45}\b(suspend(?:ed|sion)?|clos(?:ed|ure)|terminat(?:ed|ion)|delet(?:ed|ion)|lock(?:ed|out))\b|\b(suspend|close|delete|lock).{0,35}\b(account|mailbox|access)\b/i],
  ['password','Password request','The message asks for a password. Legitimate support teams should not ask you to send your password by email.',/\b(send|share|reply with|provide|confirm|enter|verify|submit).{0,35}\b(password|passcode|login credentials)\b|\b(password|credentials).{0,35}\b(send|share|reply|provide|confirm|verify)\b/i],
  ['mfa','MFA or verification code request','It asks for a one-time, MFA, or verification code. Sharing these can let someone sign in as you.',/\b(mfa|one[- ]time|verification|authentication|security) code\b|\b(code|otp).{0,40}\b(reply|send|share|provide|confirm)\b/i],
  ['payment','Payment, wire, or gift-card request','It asks for a payment, wire transfer, or gift card. Confirm money requests through a known contact channel.',/\b(gift cards?|wire transfer|wire payment|pay (the )?(fee|amount)|payment (is )?due|transfer funds|send (the )?money|crypto(currency)? payment)\b/i],
  ['bank','Bank-detail change request','It asks you to use changed bank details. Verify payment changes with a known supplier contact before paying.',/\b(new|updated|changed|change of|revised) bank details\b|\b(bank account|routing number|account number).{0,40}\b(change|update|new|revised)\b/i],
  ['invoice','Unexpected invoice or invoice pressure','Invoice or payment language appears in a message that may be unexpected. Check the sender and purchase independently.',/\b(invoice|remittance|purchase order|overdue balance|billing statement)\b/i],
  ['credential','Credential-harvesting language','It asks you to sign in, re-authenticate, or verify an account through the message. Go to the official service yourself instead.',/\b(re-?authenticat|sign[ -]?in to|log[ -]?in to|verify your (account|identity|mailbox)|confirm your (account|identity)|secure sign[ -]?in|credentials)\b/i],
  ['impersonation','Brand or authority impersonation language','It uses an organisation, IT desk, delivery, or authority identity to build trust. Check the actual sender address carefully.',/\b(microsoft 365|microsoft|it (help)?desk|security desk|support team|payroll|human resources|parcel|delivery|bank security)\b/i],
  ['macros','Request to enable macros','It asks you to enable macros or active content in an attachment, a common route for running harmful code.',/\b(enable|allow|turn on).{0,35}\b(macros?|active content)\b|\b(macros?|active content).{0,35}\b(enable|allow|turn on)\b/i]
];
const input = document.getElementById('emailInput');
const grid = document.getElementById('sampleGrid');
const resultContent = document.getElementById('resultContent');
const emptyState = document.getElementById('emptyState');
const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

samples.forEach((sample, index) => {
  const button = document.createElement('button'); button.type = 'button'; button.className = 'sample-button';
  button.innerHTML = `${escapeHtml(sample.name)} <span>${sample.level}</span>`;
  button.addEventListener('click', () => { input.value = sample.text; updateCount(); analyse(); }); grid.append(button);
});
function updateCount(){ document.getElementById('charCount').textContent = `${input.value.length.toLocaleString()} characters`; }
input.addEventListener('input', updateCount);
document.getElementById('clearButton').addEventListener('click', () => { input.value=''; updateCount(); input.focus(); resultContent.hidden=true; emptyState.hidden=false; });
document.getElementById('analyseButton').addEventListener('click', analyse);

function addFinding(list, title, explanation, weight, evidence){
  if (evidence) list.push({title, explanation, weight, evidence: evidence[0]});
}
function analyse(){
  const text = input.value.trim();
  if (!text){ input.focus(); input.setAttribute('aria-invalid','true'); setTimeout(()=>input.removeAttribute('aria-invalid'),900); return; }
  const findings=[]; const lower=text.toLowerCase();
  for(const [key,title,explanation,pattern] of rules){const match=text.match(pattern);if(match)addFinding(findings,title,explanation,weights[key],match);}
  const urls=[...text.matchAll(/(?:https?:\/\/|www\.)[^\s<>"']+/gi)].map(m=>m[0].replace(/[),.;!?]+$/,''));
  const normalized=urls.map(u=>u.replace(/^www\./i,'https://').replace(/^hxxps?:\/\//i,'https://').replace(/\[\.\]/g,'.'));
  const shortHosts=['bit.ly','tinyurl.com','t.co','is.gd','ow.ly','rebrand.ly','cutt.ly','shorturl.at'];
  if(normalized.some(u=>{try{return shortHosts.includes(new URL(u).hostname.toLowerCase())}catch{return false}}))addFinding(findings,'Shortened URL','A link uses a URL-shortening service, which hides its final destination.',weights.shortened,urls);
  if(normalized.some(u=>{try{return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(new URL(u).hostname)}catch{return false}}))addFinding(findings,'URL uses a raw IP address','A link points to a numeric IP address instead of a normal domain name.',weights.rawIp,urls);
  if(normalized.some(u=>{try{const host=new URL(u).hostname;return /(^|\.)(xn--|[^.]+-[^.]+-)/i.test(host)||host.split('.').length>4||/\d{4,}/.test(host)||/\.(zip|mov|top|click|work|support)$/i.test(host)}catch{return false}}))addFinding(findings,'Unusual or deceptive-looking URL','At least one link has a domain pattern that deserves extra scrutiny. The analyser cannot check where a link redirects.',weights.suspiciousUrl,urls);
  const links=[...text.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi)];
  let mismatch=false;
  for(const [,href,body] of links){const shown=(body.replace(/<[^>]*>/g,'').match(/(?:https?:\/\/)?[\w.-]+\.[a-z]{2,}/i)||[])[0];if(shown){try{if(new URL(href.startsWith('http')?href:`https://${href}`).hostname.toLowerCase()!==new URL(shown.startsWith('http')?shown:`https://${shown}`).hostname.toLowerCase())mismatch=true}catch{}}}
  for(const line of text.split(/\n/)){const found=line.match(/(https?:\/\/\S+|www\.[^\s]+)\s*(?:\(|\[)?\s*(?:label|displayed as|link text)\s*[:=]\s*([^\])]+)/i);if(found){try{if(new URL(found[1].startsWith('http')?found[1]:`https://${found[1]}`).hostname!==new URL(found[2].startsWith('http')?found[2]:`https://${found[2]}`).hostname)mismatch=true}catch{}}}
  if(mismatch)addFinding(findings,'Link text does not match its destination','The visible link text and the actual link destination appear to use different domains.',weights.misleading,['link']);
  const attachmentMatches=[...text.matchAll(/\b(?:attachment\s*:\s*)?([\w .()_-]+\.(?:exe|scr|bat|cmd|com|js|vbs|ps1|msi|hta|jar|docm|xlsm|pptm|iso|img|lnk))\b/gi)];
  const dangerous=attachmentMatches.filter(m=>/\.(exe|scr|bat|cmd|com|js|vbs|ps1|msi|hta|jar|iso|img|lnk)$/i.test(m[1]));
  if(attachmentMatches.length)addFinding(findings,'Unusual attachment filename','The email mentions an attachment type that deserves caution. File extensions can be disguised; do not open it to test.',weights.attachment,attachmentMatches.map(m=>m[1]));
  if(dangerous.length)addFinding(findings,'Executable or script attachment','An attachment appears to be executable or scriptable, which can run code on a device.',weights.executable,dangerous.map(m=>m[1]));
  const from=(text.match(/^from:\s*.*?<([^>]+)>/im)||text.match(/^from:\s*([^\s;]+)/im)||[])[1];
  const reply=(text.match(/^reply-to:\s*.*?<([^>]+)>/im)||text.match(/^reply-to:\s*([^\s;]+)/im)||[])[1];
  if(from&&reply){const domain=e=>e.trim().toLowerCase().split('@').pop().replace(/[>;,].*$/,'');if(domain(from)!==domain(reply))addFinding(findings,'Sender and Reply-To domains differ','The Reply-To address uses a different domain from the From address. This can redirect your response to someone else.',weights.replyMismatch,[`${from} → ${reply}`]);}
  const auth=text.match(/authentication-results:\s*([^\n]+)/i);let authNote='';
  if(auth){const line=auth[1];for(const kind of ['spf','dkim','dmarc']){const state=(line.match(new RegExp(`\\b${kind}\\s*=\\s*(pass|fail|softfail|neutral|none)\\b`,'i'))||[])[1];if(state&&/^(fail|softfail)$/i.test(state)){const title=`${kind.toUpperCase()} authentication failure`;const messages={spf:'SPF did not pass. The receiving mail system reports that the sender may not be authorised for this domain.',dkim:'DKIM did not pass. The message signature could not be verified by the receiving mail system.',dmarc:'DMARC did not pass. The sender domain policy reports an alignment or authentication problem.'};addFinding(findings,title,messages[kind],weights[kind],[`${kind}=${state}`]);}else if(state)authNote+=`${kind.toUpperCase()} ${state.toUpperCase()} · `;}}
  findings.sort((a,b)=>b.weight-a.weight);
  const raw=findings.reduce((sum,item)=>sum+item.weight,0), score=Math.min(100,raw);
  const risk=score>=60?{name:'High Risk',color:'#ff8585',border:'#714044',bg:'#4c25251f',badge:'#8d35351f',heading:'Several strong warning signs found.',next:['Do not click links, reply, or open attachments in this message.','Verify the request using the organisation’s official app, website, or a known phone number.','If you already shared information or paid, contact your IT or security team and your bank promptly.']} : score>=25?{name:'Suspicious',color:'#ffc174',border:'#684b2b',bg:'#6d451a1c',badge:'#bb76211e',heading:'Take a moment to verify this message.',next:['Avoid using links or contact details included in the email.','Check the request using the organisation’s official app, website, or a known contact.','If it is unexpected, report it using your organisation’s normal process.']} : {name:'Low Risk',color:'#71debf',border:'#27534d',bg:'#1e67551a',badge:'#1e67552a',heading:'Few common warning signs were detected.',next:['This result does not prove the email is safe. Stay alert to unusual requests.','If the message asks for money, credentials, or sensitive data, verify independently.','Open attachments only when you expected them and trust the sender.']};
  const scoreExplanation=raw>100?`Contributions total ${raw}; the displayed score is capped at 100.`:`Score equals the sum of ${findings.length} detected indicator${findings.length===1?'':'s'}.`;
  const evidenceLine=item=>item.evidence?`<br><span class="evidence">Matched: ${escapeHtml(String(item.evidence).slice(0,110))}</span>`:'';
  resultContent.innerHTML=`<div class="result-topline"><span class="result-label">02 · ANALYSIS RESULT</span><button class="reset-result" type="button" id="resetResult">New analysis</button></div><div class="score-card" style="--accent:${risk.color};--result-border:${risk.border};--result-bg:${risk.bg};--badge-bg:${risk.badge}"><div class="score-ring" style="--score:${score}"><div class="score-number">${score}<small>OF 100</small></div></div><div class="score-copy"><span class="risk-class">${risk.name.toUpperCase()}</span><h3>${risk.heading}</h3><p>Risk score is a guide based on the signals below.</p></div></div><p class="score-explain">${scoreExplanation} Each indicator has a fixed weight; total is capped at 100.</p>${findings.length?`<h3 class="findings-title">WARNING SIGNS <span>${findings.length} found</span></h3><div class="findings-list">${findings.map(item=>`<article class="finding"><div class="finding-head"><strong class="finding-title">${escapeHtml(item.title)}</strong><span class="finding-weight">+${item.weight} pts</span></div><p>${escapeHtml(item.explanation)}${evidenceLine(item)}</p></article>`).join('')}</div>`:`<div class="no-findings"><strong>No listed warning signs matched.</strong><br>This does not prove the message is legitimate. The checks are limited to known text patterns and cannot confirm a sender’s identity.</div>`}${auth?`<p class="auth-details">Header result seen: ${escapeHtml(authNote||'Authentication fields were present.')} Header text may be copied or forged; treat it as a clue, not proof.</p>`:''}<section class="safe-next"><h3>WHAT TO DO NEXT</h3><ul>${risk.next.map(line=>`<li>${escapeHtml(line)}</li>`).join('')}</ul></section>`;
  resultContent.hidden=false;emptyState.hidden=true;document.getElementById('resetResult').addEventListener('click',()=>{resultContent.hidden=true;emptyState.hidden=false;input.focus();});
}
