# Impossible Travel / Anomalous Geolocation

## Indicators
- Successful authentications from two locations whose distance could not be
  covered in the elapsed time (rule of thumb: implied speed > 800 km/h).
- New country never previously seen for the user, especially paired with a new
  device or user agent.
- Corporate VPN egress points can legitimately teleport users — check whether
  the IP belongs to a known VPN range or hosting provider.

## Risk Guidance
- Impossible travel between two SUCCESS logins: high risk (70-90).
- Impossible travel where the second location also issued token grants or
  password/MFA changes: critical (90-100).
- New-but-plausible travel (e.g. user's first login from a neighboring country,
  normal speed): low-moderate (20-45).

## False Positives
- Mobile carrier IP geolocation is coarse; a phone hopping cell towers can
  appear to move hundreds of km. Same device + same session id lowers risk.
