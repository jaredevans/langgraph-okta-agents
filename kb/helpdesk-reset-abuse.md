# Help-Desk Social Engineering / Password Reset Abuse

## Indicators
- Password reset or account unlock (`user.account.reset_password`,
  `user.account.unlock`) occurring AFTER failed authentication attempts from
  an unfamiliar IP — the attacker failed to guess, then talked the help desk
  (or a self-service flow) into a reset.
- Reset/unlock followed by immediate successful login from a DIFFERENT
  location than the user's history, then MFA factor changes (see
  privileged-activity) — the full Scattered-Spider-style chain.
- Resets requested outside business hours or clustered for several
  unrelated users in a short window (vishing campaign against the help
  desk).
- Self-service recovery events (`user.account.recovery`) from IPs/geos the
  user has never used.

## Risk Guidance
- Failed auth from new geo → reset/unlock → success from that same new geo:
  high to critical (80-95). The reset converted a failed attack into a
  successful one.
- Reset followed by factor enrollment or factor reset within the hour:
  critical (85-100) — attacker consolidating control.
- Reset during business hours, login continues from the user's usual
  location and device: low (5-20) — routine forgotten password.
- 3+ resets across different users from the same source IP or in one hour:
  treat as a campaign; score each affected user at least high (75+).

## False Positives
- Post-vacation Mondays and password-expiry waves produce reset clusters —
  these come from usual per-user locations, unlike campaign clusters which
  share a source or timing but not geography history.
