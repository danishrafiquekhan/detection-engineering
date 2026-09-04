**case-b-invoice-fraud**

Invoice-fraud BEC delivered through authenticated bulk-mail sending
infrastructure to a finance distribution list. See `../README.md` for why
this delivery method works.

**What is in here**

- `bulk-mail-invoice-fraud.yml`: the Sigma rule
- `extract_iocs.py`: pulls sender IP, message ID, and sending domain out of
  a batch of email headers, plus a volume-by-sender rollup
- `sample-data/sample-email-headers.json`: six synthetic messages, three
  are the actual attack burst, one is a different bulk-mail provider doing
  the same thing, one is a legitimate Mailchimp newsletter (no theme, DMARC
  passes), one is a legitimate SendGrid-relayed vendor invoice (DKIM
  aligns to the vendor's own domain, DMARC passes) — the last two exist to
  show the extraction script pulling IOCs out of clean traffic too, not
  just the malicious rows

**Running it**

```bash
python3 extract_iocs.py sample-data/sample-email-headers.json
python3 extract_iocs.py sample-data/sample-email-headers.json --format csv --out iocs.csv
```

No dependencies beyond the standard library. Output is IOC extraction
only, not a verdict — whether a given row is actually fraud is a judgment
the analyst makes using this output alongside the Sigma rule's other
conditions (recipient, subject theme), not something this script decides
on its own.
