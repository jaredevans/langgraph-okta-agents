# Payroll and HR Application Fraud (Workday Targeting)

## Indicators
- Compromised-looking session (failed auth burst, MFA fatigue, new device,
  or anomalous geography) followed promptly by SSO into Workday or another
  HR/payroll application. Attackers monetize identity compromise fastest by
  redirecting direct deposit.
- Workday access as the FIRST or ONLY app touched after a suspicious
  authentication — real users typically land on mail/dashboard first;
  attackers go straight to the payout.
- Workday sessions from IPs or countries never seen for the user,
  particularly around payroll cutoff dates (mid-month and month-end).
- Multiple distinct users accessing Workday from the same unfamiliar IP —
  one attacker cycling through phished accounts.

## Risk Guidance
- Any compromise indicator + Workday SSO in the same session or within
  minutes: high to critical (80-95). The blast radius is the employee's
  paycheck and PII (SSN, bank details, W-2).
- Same unfamiliar IP touching Workday for 2+ users: critical (90-100) —
  campaign, not an isolated incident.
- Workday SSO from usual device/geo with an otherwise clean session: benign
  (0-10); it is one of the most-used apps in any tenant.

## False Positives
- Payroll-adjacent staff (HR, finance) access Workday constantly, including
  odd hours during payroll runs — baseline their patterns before scoring.
- Open-enrollment and review seasons cause org-wide Workday spikes from
  home networks and personal devices.
