# MFA Fatigue / Push Bombing

## Indicators
- Repeated failed MFA challenges in a short period. Depending on tenant
  logging these appear as `user.mfa.okta_verify.deny_push` (explicit push
  denial) or, more commonly, `user.authentication.auth_via_mfa` with outcome
  `FAILURE`, `ABANDONED`, or `UNANSWERED` — the user is rejecting, ignoring,
  or timing out unsolicited prompts.
- MFA prompts triggered by sign-ins the user did not initiate, often from an
  unfamiliar IP or geography; the password stage SUCCEEDS but the MFA stage
  repeatedly fails.
- `ABANDONED`/`UNANSWERED` outcomes with blank client geo/user-agent often
  accompany automated prompt generation rather than a human at the login page.
- Eventual MFA SUCCESS after many failures suggests the user finally accepted
  a malicious prompt (or the attacker switched factor).

## Risk Guidance
- 3+ failed/abandoned MFA challenges in under 30 minutes: high risk (70-85) —
  credentials are already compromised; the attacker has the password and is
  attacking the second factor.
- Failure burst followed by a successful authentication from an unfamiliar
  location: critical (85-100).
- Mixed outcomes (some FAILURE, some ABANDONED/UNANSWERED) across one burst
  still count as a single fatigue campaign — score the burst, not the labels.

## False Positives
- One or two failures followed by success from the user's usual location:
  likely an accidental double-prompt or slow phone — low risk (10-25).
- A user mid-commute may time out (`UNANSWERED`) prompts they initiated
  themselves; consistent geo and device across the burst lowers risk.
