**bec-phishing**

Two BEC/phishing detections, chosen because they are close to opposite ends
of the same threat: one abuses infrastructure with a good reputation to
get past filters, the other has no reputation at all and relies purely on
a name match and urgency.

**What is in here**

- `case-b-invoice-fraud/`: invoice-fraud BEC delivered through authenticated
  bulk-mail sending services (SendGrid, Mailchimp) targeting a finance
  distribution list
- `case-c-executive-impersonation/`: executive-impersonation BEC from an
  external personal email address, no DKIM/DMARC alignment, urgent payment
  instructions

Same note as `guid-triage/`: neither Sigma rule here is part of the
tracked 8-rule pipeline in `sigma-rules/` / `attack-mapping.csv`. They live
in their own case folders alongside the supporting scripts and writeups
they belong with.

**Case B: why authenticated bulk-mail services are a common BEC delivery
method**

SendGrid, Mailchimp, and similar services exist so a legitimate customer
does not have to run their own mail server and fight to keep its IP
reputation clean. That is also exactly what makes them useful to an
attacker: SPF and DKIM on a message sent through SendGrid check out
against SendGrid's own domain, because SendGrid's own infrastructure
genuinely sent it. The message inherits the sending platform's reputation,
not the attacker's. A filter that leans on "is this a known-good sending
IP/domain" as its main signal will wave it through, because by that
narrow measure, it is one.

That is also exactly why this rule cannot lean on authentication results
as its distinguishing signal, and does not: `bulk-mail-invoice-fraud.yml`
requires SPF/DKIM pass from the bulk-mail domain (that part is expected
and normal), and instead keys on the combination that is not normal, the
recipient being a finance mailbox and the subject carrying invoice/payment
language, arriving as a burst. `extract_iocs.py`'s `volume_by_sender`
rollup is the concrete version of that "burst" signal, see
`case-b-invoice-fraud/README.md` for how to run it.

Same aggregation gap as `password-spray.yml` elsewhere in this repo: Sigma
expresses the per-event condition (recipient, sender infra, subject
theme) cleanly, but "high volume" is a count over a time window, which
plain Sigma has no clean way to express in a single rule. This rule's
`falsepositives` section documents that the per-event condition alone will
also match a single legitimate SendGrid-sent invoice from a real vendor,
same honest gap, same reason: the aggregation belongs at the query/SIEM
layer, not inside the Sigma file.

**Case C: executive impersonation**

No bulk-mail infrastructure to hide behind here, so this one leans on
authentication failing and a maintained list of protected display names
instead. `executive-impersonation.yml` fires on a display-name match to
that list combined with a non-corporate sending domain and an SPF/DKIM/
DMARC failure. `bec-impersonation-indicators.md` is the broader, reusable
version of the same idea, five signal categories (external sender,
impersonation indicators, targeting pattern, technical signals, risk
assessment) that generalize past any one org's protected-name list.

**A note on the fictional data**

`ap-finance@contoso.com`, the protected executive names (Alex Whitfield,
Priya Raman, Morgan Reyes), the lookalike domains, and every IP address in
`case-b-invoice-fraud/sample-data/` (the RFC 5737 documentation ranges,
same as the rest of this repo) are made up. Nothing in this folder is
modeled on a real incident or a real organization.
