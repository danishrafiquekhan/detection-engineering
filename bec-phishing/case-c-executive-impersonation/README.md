**case-c-executive-impersonation**

Executive-impersonation BEC from an external personal email address, no
DKIM/DMARC alignment, urgent payment instructions. No bulk-mail
infrastructure involved, unlike case B, this one is a straightforward
display-name spoof from a free/personal domain.

**What is in here**

- `executive-impersonation.yml`: the Sigma rule, fires on a protected
  display name arriving from a non-corporate domain with SPF/DKIM/DMARC
  failing
- `bec-impersonation-indicators.md`: a one-page, org-agnostic reference
  sheet of five BEC impersonation signal categories, meant to generalize
  past this specific rule's protected-name list

**The protected-name list**

`executive-impersonation.yml` matches on three fictional names (Alex
Whitfield, Priya Raman, Morgan Reyes) for a fictional org (contoso.com).
Real use of this pattern means maintaining that list against actual
executive/finance-leadership names for the org it protects, and reviewing
it periodically, a name that is too short or too common (a first name
alone) will false-positive against unrelated external senders who happen
to share it, see the rule's own `falsepositives` section.
