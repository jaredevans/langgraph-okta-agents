# Password Spray Attacks Against Okta

## Indicators
- Many FAILED authentication events (`user.session.start`, `user.authentication.*`
  with outcome FAILURE) across a short window.
- Failures originate from one IP or a small IP set, often hosting/VPN providers.
- Attempts spread across many accounts with few tries each (spray), or many tries
  against one account (brute force).
- A single SUCCESS following a failure burst is a strong compromise indicator.

## Risk Guidance
- Failure burst with no success: moderate risk (40-60).
- Failure burst followed by SUCCESS from the same IP: high risk (75-95).
- Success from a country the user has never authenticated from: add 10-15.

## False Positives
- A user mistyping a recently rotated password: few failures, familiar IP/geo,
  then success — low risk (0-20).
