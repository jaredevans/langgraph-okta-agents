# Session Hijacking and Cookie Theft

## Indicators
- The same Okta session id (`authentication_context.external_session_id` /
  root_session_id) used from two different IPs, user agents, or countries.
- Activity continuing after the user's typical hours from a new IP without a
  fresh authentication event (no session.start preceding activity).
- SSO into sensitive apps (admin consoles, HR, finance) from a session whose
  origin differs from the authentication origin.

## Risk Guidance
- Same session, two countries: high risk (75-90).
- Hijacked session touching admin or HR apps: critical (90-100).

## False Positives
- Corporate proxies and VPN failover can rotate egress IPs mid-session within
  the same country/provider — moderate down-weight if geo is consistent.
