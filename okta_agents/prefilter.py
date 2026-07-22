"""Deterministic (no-LLM) pre-filter: 116K rows -> a few CandidateCases."""

from math import asin, cos, radians, sin, sqrt

import pandas as pd

from okta_agents.models import CandidateCase, OktaEvent

AUTH_EVENT_PREFIXES = ("user.authentication", "user.session.start")
IMPOSSIBLE_SPEED_KMH = 800.0
MIN_TRAVEL_KM = 500.0
RARE_COUNTRY_MAX_SHARE = 0.05
RARE_COUNTRY_MIN_EVENTS = 20
SENSITIVE_EVENT_PREFIXES = (
    "user.session.impersonation",
    "user.account.privilege",
    "system.api_token",
    "user.mfa.factor.deactivate",
    "user.mfa.factor.reset_all",
    "policy.lifecycle",
)

# Shared/service-style accounts excluded from candidate selection: their
# multi-operator usage looks like impossible travel / auth anomalies.
IGNORED_USER_PREFIXES = ("gts.", "oktaprod.", "hd.")
# The organization's own trusted networks by /16 (campus + VPN/cloud egress). Activity from here is an
# on-site employee/student and is honest by definition — it never contributes
# to activity-based suspicion signals and can never be a campaign attack block.
# (Kept as the honest anchor for impossible travel, so an attack login paired
# against a trusted login is still caught.)
HOME_NETWORK_PREFIXES = ("134.231", "192.26")
NEW_DEVICE_EVENT = "system.email.new_device_notification.sent_message"
WORKDAY_APP = "Workday"
NEW_DEVICE_WINDOW = pd.Timedelta(minutes=7)

# Shared-IP campaign detection. A /16 QUALIFIES as a campaign block when
# multiple users get enrollment-type events from it (or a push-bombing burst,
# see PUSH_BOMB_MIN). Once a block qualifies, EVERY identifiable user with any
# activity from it is flagged — the attacker is using their already-
# compromised passwords, so ordinary-looking sessions from the block are the
# attacker too.
CAMPAIGN_ENROLL_EVENTS = {
    "system.email.new_device_notification.sent_message",
    "device.user.add",
    "system.email.mfa_enroll_notification.sent_message",
    "device.enrollment.create",
}
# Factor-send events (push and SMS). These fire on every MFA login, so alone
# they only qualify a block via a bombing burst (PUSH_BOMB_MIN to one user).
CAMPAIGN_SEND_EVENTS = {
    "system.push.send_factor_verify_push",
    "system.sms.send_factor_verify_message",
}
# Okta attributes factor sends and some notifications to a system principal
# (actor = "Okta System"); the real victim is in target0. load_logs
# re-attributes these to the target user so they count under the victim.
TARGET_ATTRIBUTED_EVENTS = CAMPAIGN_SEND_EVENTS | CAMPAIGN_ENROLL_EVENTS
# Push/SMS sends fire on every routine MFA login, so alone they only qualify a
# block when some user is being bombed with at least this many.
PUSH_BOMB_MIN = 10
CAMPAIGN_MIN_USERS = 3
# On broad exports (>= MIN_PREFIXES_FOR_ORG_EXEMPTION distinct /16s), a real
# campaign is time-compressed: qualification requires the multi-user activity
# to cluster within this window, and victims must show evidence (campaign
# activity or failed auth from the block) inside it. Narrow query files (an
# analyst already scoped one suspect block) keep whole-file membership
# semantics — the file itself is the window.
CAMPAIGN_WINDOW = pd.Timedelta(hours=24)
# A /16 carrying more than this share of all user events is the org's own
# network (campus/VPN egress) — exempt from campaign detection. The exemption
# only applies to broad exports: a narrow query file (few distinct /16s, e.g.
# an Okta search filtered to one suspect prefix) has no org baseline, and the
# dominant prefix there is the suspect itself.
ORG_PREFIX_MAX_SHARE = 0.10
MIN_PREFIXES_FOR_ORG_EXEMPTION = 10
# A qualified block with more distinct member users than this is shared
# carrier/org infrastructure (e.g. the org's mobile carrier /16), not a
# targeted attack — an attacker works a short list, a carrier has dozens.
CAMPAIGN_MAX_VICTIMS = 15
# A campaign block must be hosting/datacenter space, where attackers run
# automated MFA-defeat tooling — not a residential/mobile carrier where the
# org's own employees live. Datacenter IPs geolocate with no city; residential
# and mobile carrier IPs resolve to real cities. A block qualifies only if at
# least this fraction of its events have a blank city.
DATACENTER_MIN_BLANK_CITY = 0.7

WEIGHTS = {
    "failed_auth": 0.3,
    "mfa_denied": 0.5,
    "impossible_travel": 2.0,
    "rare_country": 1.0,
    "sensitive_event": 1.0,
    "workday_new_device": 3.0,
    "ip_mfa_campaign": 3.0,
}

# Users with any of these signals are near-confirmed compromises: always
# selected as cases, without consuming top-N slots.
ALWAYS_SELECT_SIGNALS = ("workday_new_device", "ip_mfa_campaign")


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    lat1, lon1, lat2, lon2 = map(radians, (lat1, lon1, lat2, lon2))
    a = sin((lat2 - lat1) / 2) ** 2 + cos(lat1) * cos(lat2) * sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * asin(sqrt(a))


def load_logs(path: str, limit_rows: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(path, nrows=limit_rows, dtype=str, keep_default_na=False)
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["ts"])
    df = _reattribute_system_factor_sends(df)
    df = df[(df["actor.type"] == "User") & df["actor.alternate_id"].str.contains("@")]
    return df.sort_values("ts")


def _reattribute_system_factor_sends(df: pd.DataFrame) -> pd.DataFrame:
    """Move factor-send/notification events from the Okta System actor to their
    real victim (target0), so the User filter keeps them and per-user grouping
    is correct. The send-origin client.ip_address is left untouched."""
    if "target0.alternate_id" not in df.columns or "target0.type" not in df.columns:
        return df
    remap = (
        df["event_type"].isin(TARGET_ATTRIBUTED_EVENTS)
        & (df["actor.type"] != "User")
        & (df["target0.type"] == "User")
        & df["target0.alternate_id"].str.contains("@")
    )
    if remap.any():
        df = df.copy()
        df.loc[remap, "actor.alternate_id"] = df.loc[remap, "target0.alternate_id"]
        df.loc[remap, "actor.display_name"] = df.loc[remap, "target0.display_name"]
        df.loc[remap, "actor.type"] = "User"
    return df


def _is_auth(df: pd.DataFrame) -> pd.Series:
    return df["event_type"].str.startswith(AUTH_EVENT_PREFIXES)


def _is_home(df: pd.DataFrame) -> pd.Series:
    return df["client.ip_address"].str.startswith(HOME_NETWORK_PREFIXES)


def _count_impossible_travel(user_df: pd.DataFrame) -> tuple[int, list[str]]:
    logins = user_df[_is_auth(user_df)].copy()
    lat = pd.to_numeric(logins["client.geographical_context.geolocation.lat"], errors="coerce")
    lon = pd.to_numeric(logins["client.geographical_context.geolocation.lon"], errors="coerce")
    logins = logins.assign(geo_lat=lat, geo_lon=lon).dropna(subset=["geo_lat", "geo_lon"]).sort_values("ts")
    count, details = 0, []
    prev = None
    for row in logins.itertuples():
        if prev is not None:
            hours = (row.ts - prev.ts).total_seconds() / 3600
            km = haversine_km(prev.geo_lat, prev.geo_lon, row.geo_lat, row.geo_lon)
            if km > MIN_TRAVEL_KM and (hours <= 0 or km / hours > IMPOSSIBLE_SPEED_KMH):
                count += 1
                details.append(
                    f"impossible travel: {km:.0f} km in {hours:.1f}h "
                    f"({prev.ts.isoformat()} -> {row.ts.isoformat()})"
                )
        prev = row
    return count, details


def _count_workday_new_device(user_df: pd.DataFrame) -> tuple[int, list[str]]:
    """Failed auth earlier, then a new-device email, then Workday SSO within 7 min.

    A newly enrolled device jumping straight into the payroll/HR app right
    after failed sign-in attempts is a strong account-takeover indicator.
    """
    notices = user_df[user_df["event_type"] == NEW_DEVICE_EVENT]
    if notices.empty:
        return 0, []
    fail_times = user_df.loc[
        _is_auth(user_df) & (user_df["outcome.result"] != "SUCCESS"), "ts"
    ]
    workday_times = user_df.loc[
        (user_df["event_type"] == "user.authentication.sso")
        & (user_df["target0.display_name"] == WORKDAY_APP)
        & (user_df["outcome.result"] == "SUCCESS"),
        "ts",
    ]
    count, details = 0, []
    for notice_ts in notices["ts"]:
        had_prior_fail = bool((fail_times < notice_ts).any())
        followed = workday_times[
            (workday_times >= notice_ts) & (workday_times <= notice_ts + NEW_DEVICE_WINDOW)
        ]
        if had_prior_fail and not followed.empty:
            count += 1
            delta = (followed.iloc[0] - notice_ts).total_seconds()
            details.append(
                f"failed auth then new-device email at {notice_ts.isoformat()} "
                f"followed by Workday SSO {delta:.0f}s later"
            )
    return count, details


def _campaign_hits(df: pd.DataFrame) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """Detect /16 IP blocks running MFA-defeat campaigns across users.

    An attacker who already has passwords works from one IP range, triggering
    device/MFA-enrollment events (or push-bombing) for MANY accounts. Every
    identifiable user active from a qualifying block is a victim.
    Returns ({user_email: {prefix: activity_count}}, {prefix: distinct_users}).
    """
    ip = df[df["client.ip_address"].str.contains(r"^\d+\.\d+\.", regex=True, na=False)].copy()
    if ip.empty:
        return {}, {}
    ip["_prefix"] = ip["client.ip_address"].str.extract(r"^(\d+\.\d+)\.")[0]
    broad_export = ip["_prefix"].nunique() >= MIN_PREFIXES_FOR_ORG_EXEMPTION
    # The trusted home network is never a campaign attack block.
    org_prefixes: set[str] = set(HOME_NETWORK_PREFIXES)
    if broad_export:
        share = ip["_prefix"].value_counts(normalize=True)
        org_prefixes |= set(share[share > ORG_PREFIX_MAX_SHARE].index)
    candidate = ip[~ip["_prefix"].isin(org_prefixes)]

    if broad_export:
        return _broad_campaign_hits(candidate)

    # Narrow query file: whole-file qualification and membership flagging.
    # Qualification: >=3 users with enrollment events, or a push-bombing burst
    # alongside >=3 users receiving pushes/enrollments.
    enroll = candidate[candidate["event_type"].isin(CAMPAIGN_ENROLL_EVENTS)]
    enroll_users = enroll.groupby("_prefix")["actor.alternate_id"].nunique()
    qualified = set(enroll_users[enroll_users >= CAMPAIGN_MIN_USERS].index)

    activity = candidate[
        candidate["event_type"].isin(CAMPAIGN_ENROLL_EVENTS)
        | (candidate["event_type"].isin(CAMPAIGN_SEND_EVENTS))
    ]
    pushes = candidate[candidate["event_type"].isin(CAMPAIGN_SEND_EVENTS)]
    push_per_user = pushes.groupby(["_prefix", "actor.alternate_id"]).size()
    bombed_prefixes = {p for (p, _), n in push_per_user.items() if n >= PUSH_BOMB_MIN}
    activity_users = activity.groupby("_prefix")["actor.alternate_id"].nunique()
    qualified |= {
        p for p in bombed_prefixes if activity_users.get(p, 0) >= CAMPAIGN_MIN_USERS
    }
    if not qualified:
        return {}, {}

    # Flagging: every identifiable user with ANY activity from a qualified
    # block. Signal value = their campaign-activity event count, floor 1.
    on_block = candidate[
        candidate["_prefix"].isin(qualified)
        & (candidate["actor.display_name"].str.lower() != "unknown")
    ]
    activity_counts = (
        activity[activity["_prefix"].isin(qualified)]
        .groupby(["actor.alternate_id", "_prefix"])
        .size()
    )
    per_user: dict[str, dict[str, int]] = {}
    for (email, prefix), _ in on_block.groupby(["actor.alternate_id", "_prefix"]):
        count = int(activity_counts.get((email, prefix), 0))
        per_user.setdefault(email, {})[prefix] = max(count, 1)
    prefix_users = {
        p: int(on_block[on_block["_prefix"] == p]["actor.alternate_id"].nunique())
        for p in qualified
    }
    return per_user, prefix_users


def _broad_campaign_hits(candidate: pd.DataFrame) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """Time-boxed campaign detection for broad exports.

    Two phases:
      1. Qualify a /16 when >=CAMPAIGN_MIN_USERS distinct users receive MFA
         factor sends or enrollment events from it within one CAMPAIGN_WINDOW
         (an attacker working a list in a burst).
      2. Flag EVERY identifiable user active from a qualified block anywhere in
         the file (membership sweep) — a clean login from a confirmed attack
         block is the attacker using a compromised password, so it counts.
    Blocks with more than CAMPAIGN_MAX_VICTIMS members are shared carrier/org
    infrastructure and are dropped. "unknown" identities excluded.
    """
    named = candidate[
        (candidate["actor.display_name"].str.lower() != "unknown")
        & candidate["_prefix"].notna()
    ]
    factor = named[named["event_type"].isin(CAMPAIGN_ENROLL_EVENTS | CAMPAIGN_SEND_EVENTS)]
    per_user: dict[str, dict[str, int]] = {}
    prefix_users: dict[str, int] = {}
    for prefix, fblock in factor.groupby("_prefix"):
        fblock = fblock.sort_values("ts")
        qualifies = any(
            fblock[(fblock["ts"] >= t) & (fblock["ts"] <= t + CAMPAIGN_WINDOW)]
            ["actor.alternate_id"].nunique() >= CAMPAIGN_MIN_USERS
            for t in fblock["ts"]
        )
        if not qualifies:
            continue
        members = named[named["_prefix"] == prefix]  # everyone active from the block
        blank_city = (members["client.geographical_context.city"] == "").mean()
        if blank_city < DATACENTER_MIN_BLANK_CITY:
            continue  # residential / mobile carrier, not datacenter attack infra
        counts = members.groupby("actor.alternate_id").size()
        if len(counts) > CAMPAIGN_MAX_VICTIMS:
            continue  # carrier / org infrastructure
        # Signal value: the user's factor-send count from the block, or 1 for a
        # login-only member (still a confirmed-block victim).
        factor_counts = fblock.groupby("actor.alternate_id").size()
        for email in counts.index:
            per_user.setdefault(email, {})[prefix] = int(factor_counts.get(email, 1)) or 1
        prefix_users[prefix] = int(len(counts))
    return per_user, prefix_users


def compute_user_signals(df: pd.DataFrame) -> dict[str, dict]:
    campaign_by_user, campaign_prefix_users = _campaign_hits(df)
    results: dict[str, dict] = {}
    for email, user_df in df.groupby("actor.alternate_id"):
        if email.lower().startswith(IGNORED_USER_PREFIXES):
            continue
        # Activity from the org's trusted home network is honest by definition:
        # exclude it from activity-based signals. Impossible travel keeps the
        # full frame — a trusted login is a legitimate anchor that still exposes
        # an attack login on the other end.
        nonhome = user_df[~_is_home(user_df)]
        failed = int((_is_auth(nonhome) & (nonhome["outcome.result"] != "SUCCESS")).sum())
        # Failed MFA events also match the failed_auth mask (user.authentication.*),
        # so they intentionally score both weights (0.3 + 0.5) — MFA failures are
        # stronger compromise evidence than plain auth failures.
        mfa_denied = int(
            (
                nonhome["event_type"].str.contains("mfa|deny_push", case=False, regex=True)
                & (nonhome["outcome.result"] != "SUCCESS")
            ).sum()
        )
        sensitive = int(nonhome["event_type"].str.startswith(SENSITIVE_EVENT_PREFIXES).sum())
        travel, travel_details = _count_impossible_travel(user_df)
        workday, workday_details = _count_workday_new_device(nonhome)
        user_campaign = campaign_by_user.get(email, {})
        campaign = sum(user_campaign.values())
        campaign_details = [
            f"{count} MFA-campaign activity event(s) on flagged IP block {prefix}.x.x "
            f"({campaign_prefix_users[prefix]} users targeted from this block)"
            for prefix, count in sorted(user_campaign.items())
        ]

        rare = 0
        rare_details: list[str] = []
        if len(user_df) >= RARE_COUNTRY_MIN_EVENTS:
            shares = user_df["client.geographical_context.country"].value_counts(normalize=True)
            for country, share in shares.items():
                if country and share < RARE_COUNTRY_MAX_SHARE:
                    rare += 1
                    rare_details.append(f"rare country for user: {country} ({share:.1%} of events)")

        signals = {
            "failed_auth": float(failed),
            "mfa_denied": float(mfa_denied),
            "impossible_travel": float(travel),
            "rare_country": float(rare),
            "sensitive_event": float(sensitive),
            "workday_new_device": float(workday),
            "ip_mfa_campaign": float(campaign),
        }
        score = sum(signals[k] * WEIGHTS[k] for k in WEIGHTS)
        if score <= 0:
            continue
        details = travel_details + rare_details + workday_details + campaign_details
        if failed:
            details.append(f"{failed} failed authentication events")
        if mfa_denied:
            details.append(f"{mfa_denied} MFA denials/failures")
        if sensitive:
            details.append(f"{sensitive} sensitive event(s) (admin/privilege/impersonation/factor-tampering)")
        results[email] = {"score": score, "signals": signals, "details": details}
    return results


def _name_slug(email: str) -> str:
    """Full name from the email local part: 'sherrod.carrington@x' -> 'sherrod-carrington'."""
    local = email.split("@")[0]
    return "".join(c if c.isalnum() else "-" for c in local).strip("-").lower()


def _row_to_event(row: pd.Series) -> OktaEvent:
    return OktaEvent(
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        display_message=row["display_message"],
        outcome=row["outcome.result"],
        actor_name=row["actor.display_name"],
        actor_email=row["actor.alternate_id"],
        ip_address=row["client.ip_address"],
        country=row["client.geographical_context.country"],
        city=row["client.geographical_context.city"],
        user_agent=row["client.user_agent.raw_user_agent"],
        app=row["target0.display_name"],
    )


def build_cases(
    df: pd.DataFrame,
    user_signals: dict[str, dict],
    max_cases: int,
    max_events: int,
) -> list[CandidateCase]:
    ranked = sorted(user_signals.items(), key=lambda kv: kv[1]["score"], reverse=True)

    def _must_select(info: dict) -> bool:
        return any(info["signals"].get(s, 0) > 0 for s in ALWAYS_SELECT_SIGNALS)

    must = [kv for kv in ranked if _must_select(kv[1])]
    rest = [kv for kv in ranked if not _must_select(kv[1])]
    selected = sorted(must + rest[:max_cases], key=lambda kv: kv[1]["score"], reverse=True)
    cases = []
    for i, (email, info) in enumerate(selected, start=1):
        user_df = df[df["actor.alternate_id"] == email].sort_values("ts").tail(max_events)
        events = [_row_to_event(row) for _, row in user_df.iterrows()]
        cases.append(
            CandidateCase(
                case_id=f"case-{i:03d}-{_name_slug(email)}",
                user_email=email,
                user_display_name=user_df.iloc[-1]["actor.display_name"],
                window_start=user_df.iloc[0]["timestamp"],
                window_end=user_df.iloc[-1]["timestamp"],
                signals=info["signals"],
                signal_details=info["details"],
                events=events,
            )
        )
    return cases
