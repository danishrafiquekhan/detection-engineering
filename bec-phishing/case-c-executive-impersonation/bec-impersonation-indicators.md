**BEC impersonation indicators — reference sheet**

One page, five signal categories. Written generic and reusable on purpose,
not tied to any one org's protected-name list, so it can travel to a
different tenant without a rewrite. `executive-impersonation.yml` in this
folder is one concrete implementation of category 1 + category 4 below.

**1. External sender**

- From domain is not the organization's own domain, or is a lookalike of it
  (character substitution, added/dropped hyphen, wrong TLD)
- From domain is a free/personal webmail provider (Gmail, Outlook.com,
  Yahoo, ProtonMail, and similar)
- Reply-To address differs from the From address, especially to a
  different domain than either
- Sending domain was registered recently (days to weeks, not years)

**2. Impersonation indicators**

- Display name matches a name on the organization's protected/executive
  list, but the underlying address does not belong to that person
- Display name uses a slightly altered spelling of a real employee's name
- Signature block claims a title or department inconsistent with the
  sending address
- Message references internal-sounding details (a project name, a team
  name) that could plausibly have been scraped from a public source
  (LinkedIn, an earnings call, a press release) rather than genuine insider
  knowledge

**3. Targeting pattern**

- Recipient is in finance, accounts payable, HR, or another
  payment/PII-adjacent function, not a random distribution
- Message requests a wire transfer, a change to payment/banking details,
  a gift card purchase, or sensitive employee data (W-2s, direct deposit
  forms)
- Urgency language: "before end of day," "can't talk right now," "keep
  this confidential," pressure to bypass a normal approval step
- Timing correlates with the impersonated executive being plausibly
  unreachable (travel, a public calendar entry, an out-of-office message)

**4. Technical signals**

- SPF, DKIM, or DMARC fail, or the domain has no DMARC policy published at
  all (`p=none` is present but not enforcing, which is common and not by
  itself a strong signal — full failure or no record is stronger)
- Message headers show a Return-Path or Received chain that does not match
  the claimed sending organization
- No prior message history between the recipient and the sending address
- Sent through infrastructure with no legitimate reason to be sending on
  behalf of this person (a bulk-mail service, a residential IP range, a
  generic VPS host)

**5. Risk assessment**

- How many of the above categories does this message actually hit, not
  just category 2 (a name match alone is weak on its own, most BEC relies
  on stacking two or three categories at once)
- What is the requested action's blast radius if it succeeds — a wire
  transfer has a materially different risk profile than a reply asking for
  a phone number
- Is the targeted recipient positioned to actually execute the request
  (do they have wire authority, HR data access) or would they need to loop
  in someone else who might catch it
- Has this display name / domain / IP been seen targeting this
  organization before (checking against a rolling IOC list turns a
  one-off judgment call into a pattern an analyst can point to)
