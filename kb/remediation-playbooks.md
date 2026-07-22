# Okta Incident Remediation Playbooks (Advisory)

All plans are drafts for human SOC review — nothing is executed automatically.

## Playbook: Compromised Credentials (spray/brute-force success)
1. Suspend the user account in Okta (Admin > Directory > People > Suspend).
2. Clear all active sessions for the user (Admin > Clear User Sessions).
3. Expire the password and force reset on next login.
4. Review the user's recent app assignments and token grants; revoke suspect
   OAuth tokens.
5. Block the offending IP/CIDR in the network zone blocklist.
6. Notify the user and their manager through an out-of-band channel.

## Playbook: MFA Fatigue
1. Clear user sessions and reset the affected MFA factor.
2. Rotate the user's password (it is already compromised).
3. Enable number-challenge / phishing-resistant factors for the user's group.
4. Review auth policy: rate-limit push attempts where possible.

## Playbook: Session Hijack
1. Clear all sessions immediately; revoke refresh tokens.
2. Force re-authentication with MFA for all the user's apps.
3. Investigate endpoint for cookie-stealing malware before restoring access.

## Playbook: Anomalous Geography (unconfirmed compromise)
1. Do not suspend yet; contact the user to verify travel.
2. Tighten the user's sign-on policy to require MFA every login temporarily.
3. Monitor for 48h; escalate to the credential playbook on further anomalies.

## Playbook: New-Device Takeover (device enrollment abuse)
1. Suspend the account and clear all sessions — the new device holds a live
   session.
2. Revoke the unrecognized device's trust/registration; reset MFA factors
   enrolled from it.
3. Rotate the password; require phishing-resistant re-enrollment in person or
   via verified video with the help desk.
4. Audit every application accessed from the new device since the
   notification (see payroll playbook if Workday/HR was touched).
5. Preserve the new-device notification email and session logs as evidence.

## Playbook: Payroll/HR Fraud (Workday accessed post-compromise)
1. Contact payroll/HR immediately: freeze direct-deposit and bank-detail
   changes for the affected user pending review.
2. Audit Workday for changes since the first suspicious login: direct
   deposit, address, tax withholding, W-2 delivery preferences.
3. Reverse unauthorized changes and flag any pending payroll run.
4. Treat the user's Okta account per the credential playbook (suspend, clear
   sessions, rotate password).
5. Notify the affected employee out-of-band; bank-detail theft may require
   fraud reporting with the receiving bank.
6. Search for other users accessed from the same source IP — payroll fraud
   is usually a campaign.

## Playbook: Privileged Activity Abuse (factor tampering / rogue grants)
1. Re-enable and re-verify the victim's MFA factors; deactivate factors the
   attacker enrolled.
2. Revert unauthorized privilege grants and policy changes; document each
   reverted change.
3. Revoke admin API tokens created during the incident window.
4. If an impersonation session was abused, suspend the impersonating admin
   account pending review and audit its other impersonation history.
5. Review admin-role assignments tenant-wide for additional persistence.

## Playbook: Shared-IP Multi-Account Campaign
1. Block the attacking /16 (or tighter CIDR from the observed IPs) in the
   Okta network zone blocklist FIRST — this stops the campaign against all
   accounts at once, including ones not yet flagged.
2. Treat every user active from the block as credential-compromised: expire
   passwords and clear sessions for the full victim list together, not one
   at a time (partial response tips off the attacker).
3. Reset/re-verify MFA factors enrolled during the campaign window; revoke
   device registrations created from the block.
4. Audit sensitive-app activity (payroll, HR, admin) for every victim during
   the window — see the payroll playbook where Workday was touched.
5. Hunt for the same block's activity in adjacent time ranges and for other
   /16s with the same behavior — attackers rotate ranges.
6. Preserve the full event set for the block as one incident record; notify
   all victims out-of-band simultaneously.

## Playbook: Help-Desk Reset Abuse
1. Invalidate the fraudulent reset: expire the new password and clear
   sessions created after the reset event.
2. Verify the user's identity through a strong channel (in-person, video, or
   manager confirmation) before restoring access.
3. Review the help-desk ticket trail for the reset; alert the help-desk team
   to the pretext used.
4. Check for other resets requested from the same source or in the same
   window; treat matches as one campaign.
5. Strengthen the reset procedure: require MFA or manager approval for
   resets requested from unrecognized locations.
