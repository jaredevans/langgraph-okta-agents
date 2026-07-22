# Shared-IP Multi-Account MFA Campaign

## Indicators
- One /16 IP block generating MFA/device-enrollment activity — factor-verify
  pushes, new-device notification emails, MFA-enroll emails,
  `device.user.add`, `device.enrollment.create` — across THREE OR MORE
  distinct accounts. One operator is working through a list of compromised
  passwords, attacking the second factor account by account.
- Push-bombing bursts (10+ factor-verify pushes to a single user) from the
  same block confirm active MFA-defeat attempts.
- Failed session starts against unresolvable or "unknown" accounts from the
  block — the attacker probing a credential list containing stale entries.
- CRITICAL NUANCE: ordinary-looking, successful sessions from a flagged
  block are NOT exculpatory. The attacker already holds these users'
  passwords; a clean SSO session from campaign infrastructure IS the
  attacker logged in as the victim. Absence of failures in one user's own
  timeline does not lower their risk when the source block is a campaign.

## Risk Guidance
- Any user flagged as active from a campaign block (pre-filter signal
  `ip_mfa_campaign` > 0): treat the password as compromised. Baseline
  high risk (75-90) even when the user's own events look routine.
- Membership plus their own enrollment/new-device/push-bomb events: critical
  (85-100) — the MFA-defeat attempt on this specific account is in progress
  or complete.
- Membership plus successful sensitive-app access (Workday, admin consoles)
  from the block: critical (90-100).
- Score the CAMPAIGN, not just the account: the number of users targeted
  from the block is itself evidence — a 7-user block is an operation, not a
  coincidence.

## False Positives
- A small office or family behind one ISP /16 can produce 2-3 users with
  legitimate enrollments; look for interleaved timing across accounts
  (attacker working a list) versus independent daytime enrollments.
- Genuinely shared corporate egress should be exempted as the org network
  by traffic share before this pattern is applied at all.
