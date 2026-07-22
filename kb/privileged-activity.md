# Privileged and Administrative Activity Abuse

## Indicators
- Impersonation sessions (`user.session.impersonation.*`): an admin or
  help-desk operator acting as another user. Legitimate for support, but
  critical when initiated outside business hours, from unusual IPs, or
  without a matching support ticket.
- Privilege grants (`user.account.privilege.grant`): a user suddenly
  receiving admin rights, especially shortly after any authentication
  anomaly for the granting or receiving account.
- MFA factor tampering (`user.mfa.factor.deactivate`,
  `user.mfa.factor.reset_all`): removing or resetting second factors is how
  an attacker with a stolen session locks in access and locks out the victim.
- API token administration (`system.api_token.*`): creating or modifying
  admin API tokens grants durable, MFA-free access that survives password
  resets.
- Policy lifecycle changes (`policy.lifecycle.*`): weakening sign-on or MFA
  policy is an org-wide persistence technique.

## Risk Guidance
- Factor deactivation/reset on an account that also shows failed auth, new
  geography, or a new device in the same window: critical (85-100) — classic
  post-compromise lockout of the real user.
- Repeated factor deactivations (3+) for one account in one day: high
  (75-90) even without other signals.
- Privilege grant or API token creation within an hour of any anomalous
  login: high (75-90); attacker establishing persistence.
- Impersonation from usual admin IP during business hours with no other
  anomalies: low-moderate (15-35) — normal help-desk work.
- Policy weakened (MFA disabled, session lifetime extended) by an account
  with any concurrent anomaly: critical (90-100).

## False Positives
- IT staff perform factor resets for users who lost phones — expect a
  help-desk impersonation or admin session immediately before, from a known
  admin IP.
- Scheduled automation (JAMF, provisioning services) creates tokens on a
  regular cadence from stable IPs; look for cadence breaks, not the events
  themselves.
