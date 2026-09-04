**guid-triage**

How to determine whether an unrecognized GUID in an alert is a real identity
or a non-identity resource ID.

**What is in here**

- `unrecognized-guid-access.yml`: a Sigma rule (matches this repo's
  `sigma-rules/` schema, but lives here instead, see "Why this is not in
  `sigma-rules/`" below) that fires when a sign-in or resource-access event
  carries a well-formed GUID as the actor but no display name for it
- `guid-identity-check.kql`: the follow-up query, checks a given GUID
  against `SigninLogs`, `AuditLogs`, and a fictional analyst-maintained
  reference table of GUIDs already confirmed to be non-identity resource IDs
- this README, the actual runbook

**Why this is not in `sigma-rules/`**

`make convert` globs `sigma-rules/*.yml` and regenerates every file in
`kql-conversions/generated/` from it, and `attack-mapping.csv` tracks that
exact set of 8 rules as "converted, not yet deployed/validated." This rule
is a real detection with a real Sigma schema, but it is not part of that
tracked pipeline, and folding it in would misrepresent both counts. It sits
in its own folder on purpose, next to the runbook it exists to trigger.

**The scenario this is based on**

An alert fired: "unrecognized GUID accessing a resource." The actor field
in the event was a syntactically valid GUID, no display name attached to
it anywhere in the alert. Nothing about the alert said whether that GUID
was a user, an app, a device, or something that was never an identity in
the first place.

It turned out to be an Azure DevOps Collection ID. Something upstream had
logged it into a field shaped like an actor identity, because to whatever
emitted the event, a GUID is a GUID. Getting from "unrecognized GUID" to
"this was never an identity" took checking four different places and
getting a 404 back from Microsoft Graph, in that order, which is the
runbook below.

**Decision flowchart**

```
Unrecognized GUID in alert
        |
        v
[1] Check Enterprise Applications (Entra admin center > Enterprise
    Applications > search by Object ID / Application ID)
        |
   found? --yes--> Real identity: a service principal. Investigate as a
        |           possible app-compromise / consent-abuse case.
        no
        v
[2] Check App Registrations (Entra admin center > App registrations,
    search by Application (client) ID)
        |
   found? --yes--> Real identity: an application registered in this
        |           tenant. Check owners, credentials, redirect URIs,
        |           and recent sign-in activity for it.
        no
        v
[3] Check Managed Identities (system-assigned and user-assigned, under
    the resource or under Entra ID > Enterprise Applications with
    "Managed Identities" as the application type filter)
        |
   found? --yes--> Real identity: a managed identity. Identify which
        |           Azure resource it is attached to and check what
        |           that resource has been doing.
        no
        v
[4] Query Microsoft Graph directly:
    GET https://graph.microsoft.com/v1.0/directoryObjects/{guid}
        |
   200 OK? --yes--> Real identity, some directory object type not
        |            covered by steps 1-3. Read the returned @odata.type
        |            and investigate accordingly.
        no (404 Not Found)
        v
[5] Not a directory identity. Check non-identity sources the GUID could
    have come from:
      - Azure DevOps: Organization ID, Collection ID, Project ID,
        Service Connection ID (Project Settings > Service connections)
      - Azure Resource ID components (subscription ID, or the GUID
        suffix on a resource name)
      - Third-party SaaS internal object IDs that happen to leak into
        logs shaped like identity fields
        |
   match found? --yes--> Non-identity resource ID. Not an identity
        |                  compromise. Add it to the known-non-identity
        |                  reference table (see "Closing the loop"
        |                  below) and close, pending a one-line
        |                  confirmation from the resource's owning team.
        no
        v
   Genuinely unknown GUID. Does not resolve as any directory object
   type and does not match any known non-identity source. Escalate,
   treat as suspicious pending further investigation.
```

**Why the order matters**

Enterprise Applications, App Registrations, and Managed Identities are
three different blades in the Entra admin center for what is, under the
hood, mostly the same `servicePrincipal`/`application` object model, and
none of them search across the other two. Checking Graph directly (step 4)
before assuming "not an identity" matters because it is the one check that
is authoritative for the whole directory at once, not just one blade's
view of it — a 404 there is a much stronger signal than "I did not find it
in the three blades I checked by hand." Steps 1-3 come first anyway
because they are faster when the GUID is a common case, and because seeing
the actual object in the admin UI carries context (owners, sign-in
activity, tags) a bare Graph JSON response does not.

**Closing the loop**

`guid-identity-check.kql` queries a fictional `KnownNonIdentityGuids_CL`
table. The idea: once step 5 above confirms a GUID is a non-identity
resource ID, add a row for it (the GUID, what kind of resource it is, who
confirmed it, when) instead of letting the next analyst who sees the same
GUID in a future alert start this whole runbook over from step 1. This
table does not exist anywhere real, it is a stand-in for "wherever this
org keeps that kind of reference data" — Sentinel watchlist, a wiki page,
a spreadsheet, whatever is available.

**A note on the fictional org**

The example GUID (`a4f8e2d1-9c3b-4a7e-8f1d-2b3c4d5e6f70`), the tenant name,
and the Azure DevOps org referenced in this folder are all made up, same
convention as the rest of this repo (`contoso-lab.onmicrosoft.com`, RFC
5737 IP ranges). This runbook is built on a real investigation pattern,
not a real incident, and no real GUID, tenant ID, or org name appears
anywhere in it.
