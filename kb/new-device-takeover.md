# New-Device Enrollment Abuse / Device-Based Account Takeover

## Indicators
- A `system.email.new_device_notification.sent_message` event — Okta telling
  the user "a new device signed into your account" — preceded by failed
  authentication events for the same user (the attacker guessing or spraying
  before succeeding).
- Sensitive-app SSO (Workday, finance, HR, admin consoles) within minutes of
  the new-device notification. Sub-minute gaps between notification and app
  access indicate scripted, non-human pacing.
- New-device notification from an IP, geography, or user agent the user has
  never used before.
- No accompanying device-management enrollment (e.g. JAMF/Okta Verify
  enrollment events) — a legitimate new corporate device usually produces an
  enrollment trail; a bare browser session that is "new" does not.

## Risk Guidance
- Failed auth earlier + new-device notification + sensitive-app SSO within
  5 minutes: high to critical risk (80-95). This is the signature of a
  completed takeover moving straight to its objective.
- Notification-to-app gap under 60 seconds: treat as scripted — add 5-10.
- Same pattern but the new device matches the user's usual geography and
  user agent, with a plausible pace (several minutes): moderate (50-65) —
  could be a real new machine, verify with the user.
- New-device notification alone, no prior failures, no immediate sensitive
  app access: low (10-25).

## False Positives
- Genuine device replacement: expect factor enrollment events, familiar
  location, and ordinary human pacing between login and app usage.
- Browser cookie clearing or private-browsing sessions can trigger new-device
  notifications for the user's usual machine — geo/UA continuity is the
  discriminator.
