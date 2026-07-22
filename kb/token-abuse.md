# OAuth Token Grant Abuse

## Indicators
- Unusual volume of `app.oauth2.token.grant.access_token` events for one user
  or client, especially outside business hours.
- Token grants from clients/apps the user has never used before.
- API token creation or grants immediately following a suspicious
  authentication (failed burst, MFA fatigue, new geography).

## Risk Guidance
- Token grants following any other compromise indicator: add 15-25 to the
  overall score; the attacker is establishing persistence.
- Isolated token grants from usual apps/locations: benign (0-10).

## False Positives
- Automated device-management clients (e.g. JAMF Connect) legitimately mint
  tokens frequently from stable IPs.
