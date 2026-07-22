from okta_agents.prefilter import (
    build_cases,
    compute_user_signals,
    haversine_km,
    load_logs,
)
from tests.conftest import make_log_df


def _t(hour: int, minute: int = 0) -> str:
    return f"2026-07-21T{hour:02d}:{minute:02d}:00.000Z"


def test_haversine_known_distance():
    # Washington DC -> Paris is roughly 6180 km
    d = haversine_km(38.9034, -76.9882, 48.8582, 2.3387)
    assert 6000 < d < 6400


def test_load_logs_filters_non_users(log_csv):
    path = log_csv(
        [
            {"actor.alternate_id": "alice@example.edu"},
            {"actor.type": "PublicClientApp", "actor.alternate_id": "0oaalhd1xkp"},
        ]
    )
    df = load_logs(path)
    assert len(df) == 1
    assert df.iloc[0]["actor.alternate_id"] == "alice@example.edu"


def test_failed_auth_burst_scores_higher_than_benign():
    rows = [
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(1, i),
         "event_type": "user.session.start", "outcome.result": "FAILURE"}
        for i in range(8)
    ] + [{"actor.alternate_id": "normal@example.edu", "timestamp": _t(2)}]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["victim@example.edu"]["score"] > 0
    assert signals["victim@example.edu"]["signals"]["failed_auth"] == 8
    assert "normal@example.edu" not in signals  # score 0 -> excluded


def test_impossible_travel_detected():
    rows = [
        {"actor.alternate_id": "traveler@example.edu", "timestamp": _t(1),
         "event_type": "user.session.start",
         "client.geographical_context.country": "United States",
         "client.geographical_context.geolocation.lat": "38.9034",
         "client.geographical_context.geolocation.lon": "-76.9882"},
        {"actor.alternate_id": "traveler@example.edu", "timestamp": _t(2),
         "event_type": "user.session.start",
         "client.geographical_context.country": "France",
         "client.geographical_context.city": "Paris",
         "client.geographical_context.geolocation.lat": "48.8582",
         "client.geographical_context.geolocation.lon": "2.3387"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["traveler@example.edu"]["signals"]["impossible_travel"] >= 1


def test_mfa_denials_scored():
    rows = [
        {"actor.alternate_id": "pushed@example.edu", "timestamp": _t(3, i),
         "event_type": "user.mfa.okta_verify.deny_push", "outcome.result": "FAILURE"}
        for i in range(4)
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["pushed@example.edu"]["signals"]["mfa_denied"] == 4


def test_sensitive_events_scored():
    rows = [
        {"actor.alternate_id": "admin@example.edu", "timestamp": _t(4),
         "event_type": "user.session.impersonation.initiate", "outcome.result": "SUCCESS"},
        {"actor.alternate_id": "admin@example.edu", "timestamp": _t(4, 5),
         "event_type": "user.account.privilege.grant", "outcome.result": "SUCCESS"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["admin@example.edu"]["signals"]["sensitive_event"] == 2
    assert signals["admin@example.edu"]["score"] >= 2.0


def test_build_cases_caps_events_and_orders_by_score(log_csv):
    rows = (
        [{"actor.alternate_id": "big@example.edu", "timestamp": _t(1, i % 60),
          "event_type": "user.session.start", "outcome.result": "FAILURE"}
         for i in range(90)]
        + [{"actor.alternate_id": "small@example.edu", "timestamp": _t(2, i),
            "event_type": "user.session.start", "outcome.result": "FAILURE"}
           for i in range(5)]
    )
    df = load_logs(log_csv(rows))
    signals = compute_user_signals(df)
    cases = build_cases(df, signals, max_cases=5, max_events=75)
    assert [c.user_email for c in cases] == ["big@example.edu", "small@example.edu"]
    assert len(cases[0].events) == 75
    assert cases[0].case_id == "case-001-big"
    assert cases[0].signals["failed_auth"] == 90


def test_workday_new_device_sequence_scored():
    rows = [
        # prior failed auth, then success, new-device email, Workday SSO 1 min later
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 0),
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 2),
         "event_type": "user.session.start", "outcome.result": "SUCCESS"},
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 3),
         "event_type": "system.email.new_device_notification.sent_message"},
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 4),
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
        # no prior failures: same email->Workday sequence must NOT score
        {"actor.alternate_id": "clean@example.edu", "timestamp": _t(10, 0),
         "event_type": "system.email.new_device_notification.sent_message"},
        {"actor.alternate_id": "clean@example.edu", "timestamp": _t(10, 1),
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
        # prior failure but Workday login 10 min after the email: outside window
        {"actor.alternate_id": "slow@example.edu", "timestamp": _t(11, 0),
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "slow@example.edu", "timestamp": _t(11, 5),
         "event_type": "system.email.new_device_notification.sent_message"},
        {"actor.alternate_id": "slow@example.edu", "timestamp": _t(11, 15),
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["victim@example.edu"]["signals"]["workday_new_device"] == 1
    assert signals["victim@example.edu"]["score"] >= 3.0  # weight 3.0 dominates
    assert "clean@example.edu" not in signals or (
        signals["clean@example.edu"]["signals"]["workday_new_device"] == 0
    )
    assert signals["slow@example.edu"]["signals"]["workday_new_device"] == 0


def test_workday_window_is_seven_minutes():
    rows = [
        {"actor.alternate_id": "six@example.edu", "timestamp": _t(9, 0),
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "six@example.edu", "timestamp": _t(9, 1),
         "event_type": "system.email.new_device_notification.sent_message"},
        {"actor.alternate_id": "six@example.edu", "timestamp": _t(9, 7),  # 6 min after email
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["six@example.edu"]["signals"]["workday_new_device"] == 1


def test_workday_sequence_counts_failed_auth_hours_earlier():
    """Only the email->Workday gap is windowed; the failed auth may be far earlier."""
    rows = [
        {"actor.alternate_id": "early@example.edu", "timestamp": _t(1, 0),
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "early@example.edu", "timestamp": _t(15, 0),  # 14h later
         "event_type": "system.email.new_device_notification.sent_message"},
        {"actor.alternate_id": "early@example.edu", "timestamp": _t(15, 3),
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["early@example.edu"]["signals"]["workday_new_device"] == 1


def test_home_network_activity_is_trusted():
    """Failed auth / MFA failures from the org's home network (134.231) are
    honest and must not raise signals; the same events from another IP do."""
    home = [
        {"actor.alternate_id": "student@example.edu", "timestamp": _t(5, i),
         "event_type": "user.session.start", "outcome.result": "FAILURE",
         "client.ip_address": "134.231.5.9"}
        for i in range(8)
    ]
    away = [
        {"actor.alternate_id": "victim@example.edu", "timestamp": _t(6, i),
         "event_type": "user.session.start", "outcome.result": "FAILURE",
         "client.ip_address": "45.9.1.1"}
        for i in range(8)
    ]
    signals = compute_user_signals(_prep(make_log_df(home + away)))
    assert "student@example.edu" not in signals  # all home activity -> no flag
    assert signals["victim@example.edu"]["signals"]["failed_auth"] == 8


def test_home_network_never_a_campaign_block(log_csv):
    rows = [
        {"actor.alternate_id": f"u{i}@example.edu", "timestamp": _t(6, i),
         "event_type": "system.email.new_device_notification.sent_message",
         "client.ip_address": f"134.231.{i}.1",
         "client.geographical_context.city": ""}
        for i in range(3)
    ]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    assert all(
        signals.get(f"u{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(3)
    )


def test_impossible_travel_keeps_home_as_honest_anchor():
    """A campus login then a far login minutes later is still impossible travel
    — the trusted end is the honest anchor exposing the attack login."""
    rows = [
        {"actor.alternate_id": "traveler@example.edu", "timestamp": _t(1),
         "event_type": "user.session.start",
         "client.ip_address": "134.231.1.1",
         "client.geographical_context.geolocation.lat": "38.9034",
         "client.geographical_context.geolocation.lon": "-76.9882"},
        {"actor.alternate_id": "traveler@example.edu", "timestamp": _t(2),
         "event_type": "user.session.start",
         "client.ip_address": "45.9.2.2",
         "client.geographical_context.geolocation.lat": "48.8582",
         "client.geographical_context.geolocation.lon": "2.3387"},
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert signals["traveler@example.edu"]["signals"]["impossible_travel"] >= 1


def test_ignored_account_prefixes_never_flagged():
    rows = [
        {"actor.alternate_id": f"{who}@example.edu", "timestamp": _t(5, i),
         "event_type": "user.session.start", "outcome.result": "FAILURE"}
        for who in ("gts.krigsman", "oktaprod.whitaker", "hd.jones", "real.person")
        for i in range(8)
    ]
    signals = compute_user_signals(_prep(make_log_df(rows)))
    assert set(signals) == {"real.person@example.edu"}


def test_workday_sequence_users_always_selected(log_csv):
    rows = (
        # noisy user: 40 failed auths -> score 12, dominates ranking
        [{"actor.alternate_id": "noisy@example.edu", "timestamp": _t(1, i % 60),
          "event_type": "user.session.start", "outcome.result": "FAILURE"}
         for i in range(40)]
        # victim: one workday sequence -> score ~3.3, would lose a top-1 cut
        + [
            {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 0),
             "event_type": "user.session.start", "outcome.result": "FAILURE"},
            {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 3),
             "event_type": "system.email.new_device_notification.sent_message"},
            {"actor.alternate_id": "victim@example.edu", "timestamp": _t(9, 4),
             "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
             "target0.display_name": "Workday"},
        ]
    )
    df = load_logs(log_csv(rows))
    cases = build_cases(df, compute_user_signals(df), max_cases=1, max_events=75)
    emails = [c.user_email for c in cases]
    assert "victim@example.edu" in emails  # must-include despite max_cases=1
    assert "noisy@example.edu" in emails  # top-N slot not consumed by must-include
    assert len(cases) == 2


def _campaign_rows():
    """3 victims getting new-device emails from 35.33.x.x, plus enough benign
    background traffic (prefix 10.0) that 35.33 is not the org's home prefix."""
    background = [
        {"actor.alternate_id": "background@example.edu", "timestamp": _t(2, i)}
        for i in range(40)
    ]
    victims = [
        {"actor.alternate_id": f"victim{i}@example.edu", "timestamp": _t(6, i),
         "event_type": "system.email.new_device_notification.sent_message",
         "client.ip_address": f"35.33.{i}.7"}
        for i in range(3)
    ]
    return background + victims


def test_ip_mfa_campaign_flags_all_users_on_shared_prefix(log_csv):
    df = load_logs(log_csv(_campaign_rows()))
    signals = compute_user_signals(df)
    for i in range(3):
        assert signals[f"victim{i}@example.edu"]["signals"]["ip_mfa_campaign"] == 1
    cases = build_cases(df, signals, max_cases=0, max_events=75)
    assert sorted(c.user_email for c in cases) == [
        "victim0@example.edu", "victim1@example.edu", "victim2@example.edu"
    ]  # always selected even with max_cases=0


def test_ip_mfa_campaign_needs_three_distinct_users(log_csv):
    rows = [r for r in _campaign_rows() if r["actor.alternate_id"] != "victim2@example.edu"]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    assert "victim0@example.edu" not in signals  # 2 users on prefix -> no campaign


def test_ip_mfa_campaign_exempts_org_home_prefix(log_csv):
    # 3 victims' events come from the dominant (org) prefix 10.0; background
    # traffic spans enough other /16s that the org exemption is active.
    rows = [
        {"actor.alternate_id": "background@example.edu", "timestamp": _t(2, i),
         "client.ip_address": "10.0.0.1"}
        for i in range(40)
    ] + [
        {"actor.alternate_id": "roamer@example.edu", "timestamp": _t(3, i),
         "client.ip_address": f"20.{i}.0.1"}
        for i in range(10)
    ] + [
        {"actor.alternate_id": f"victim{i}@example.edu", "timestamp": _t(6, i),
         "event_type": "system.email.new_device_notification.sent_message",
         "client.ip_address": "10.0.99.7"}
        for i in range(3)
    ]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    assert all(
        signals.get(f"victim{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(3)
    )


def test_ip_mfa_campaign_fires_on_narrow_query_export(log_csv):
    """A CSV filtered to one suspect prefix (e.g. an Okta query for 35.33)
    has no org baseline — the exemption must not swallow the campaign."""
    rows = [
        {"actor.alternate_id": f"victim{i}@example.edu", "timestamp": _t(6, i),
         "event_type": "system.email.new_device_notification.sent_message",
         "client.ip_address": f"35.33.{i}.7"}
        for i in range(3)
    ] + [
        {"actor.alternate_id": "victim0@example.edu", "timestamp": _t(7, 0),
         "client.ip_address": "35.33.0.7"}  # ordinary traffic, same prefix
        for _ in range(20)
    ]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    for i in range(3):
        assert signals[f"victim{i}@example.edu"]["signals"]["ip_mfa_campaign"] == 1


def test_ip_mfa_campaign_push_events_count_as_activity(log_csv):
    """send_factor_verify_push from a campaign block contributes to the
    victim's signal value (push bombing)."""
    rows = _campaign_rows() + [
        {"actor.alternate_id": "bombed@example.edu", "timestamp": _t(8, i % 60),
         "event_type": "system.push.send_factor_verify_push",
         "client.ip_address": "35.33.9.9"}
        for i in range(12)
    ]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    assert signals["bombed@example.edu"]["signals"]["ip_mfa_campaign"] == 12


def test_ip_mfa_campaign_flags_all_users_on_block_by_membership(log_csv):
    """Once a /16 qualifies, EVERY identifiable user with activity from it is
    flagged — even with only ordinary session events (attacker using their
    already-compromised password)."""
    rows = _campaign_rows() + [
        {"actor.alternate_id": "bystander@example.edu", "timestamp": _t(8, 0),
         "event_type": "user.session.start", "outcome.result": "SUCCESS",
         "client.ip_address": "35.33.200.4"},
        {"actor.alternate_id": "unknown@example.edu", "timestamp": _t(8, 1),
         "actor.display_name": "unknown",
         "event_type": "user.session.start", "outcome.result": "FAILURE",
         "client.ip_address": "35.33.200.5"},
    ]
    df = load_logs(log_csv(rows))
    signals = compute_user_signals(df)
    assert signals["bystander@example.edu"]["signals"]["ip_mfa_campaign"] == 1  # membership floor
    # unresolved identity may score on other signals (failed auth) but never
    # gets the campaign flag or guaranteed selection
    assert signals["unknown@example.edu"]["signals"]["ip_mfa_campaign"] == 0
    emails = [c.user_email for c in build_cases(df, signals, max_cases=0, max_events=75)]
    assert "bystander@example.edu" in emails  # always selected
    assert "unknown@example.edu" not in emails


def _broad_background():
    """Background traffic across 10 prefixes -> broad-export mode, with enough
    volume that a 3-6 event suspect prefix stays under the org-share cutoff."""
    return [
        {"actor.alternate_id": "roamer@example.edu", "timestamp": _t(2, (i * 10 + j) % 60),
         "client.ip_address": f"20.{i}.0.1"}
        for i in range(10)
        for j in range(8)
    ]


def _enroll_row(email, ts, ip):
    # blank city => datacenter/hosting IP (attacker infra), per the campaign gate
    return {"actor.alternate_id": email, "timestamp": ts,
            "event_type": "system.email.new_device_notification.sent_message",
            "client.ip_address": ip, "client.geographical_context.city": ""}


def test_broad_campaign_qualifies_by_day_then_sweeps_whole_file(log_csv):
    """3+ users get factor sends from 66.77 on ONE day (qualifies the block);
    a 4th user got a factor send from it two weeks later -> swept in too."""
    def send(user, ts, ip="66.77.5.5"):
        return {"actor.type": "SystemPrincipal", "actor.display_name": user.title(),
                "actor.alternate_id": "system@okta",
                "event_type": "system.sms.send_factor_verify_message",
                "timestamp": ts, "client.ip_address": ip,
                "client.geographical_context.city": "",
                "target0.type": "User", "target0.display_name": user.title(),
                "target0.alternate_id": f"{user}@example.edu"}
    rows = _broad_background() + [
        send("a", "2026-07-15T10:00:00.000Z"),
        send("b", "2026-07-15T10:05:00.000Z"),
        send("c", "2026-07-15T10:10:00.000Z"),
        send("late", "2026-07-29T09:00:00.000Z"),  # weeks later, still swept
    ]
    signals = compute_user_signals(load_logs(log_csv(rows)))
    for u in ("a", "b", "c", "late"):
        assert signals[f"{u}@example.edu"]["signals"]["ip_mfa_campaign"] >= 1


def test_broad_campaign_exempts_high_victim_carrier_block(log_csv):
    """A /16 where MANY users get factor sends is the org's carrier, not an
    attack — exempt it above CAMPAIGN_MAX_VICTIMS."""
    from okta_agents.prefilter import CAMPAIGN_MAX_VICTIMS

    def send(user, ts, ip):
        return {"actor.type": "SystemPrincipal", "actor.display_name": user,
                "actor.alternate_id": "system@okta",
                "event_type": "system.sms.send_factor_verify_message",
                "timestamp": ts, "client.ip_address": ip,
                "client.geographical_context.city": "",
                "target0.type": "User", "target0.display_name": user,
                "target0.alternate_id": f"{user}@example.edu"}
    carrier = [send(f"emp{i}", f"2026-07-15T10:{i % 60:02d}:00.000Z", f"90.90.{i}.1")
               for i in range(CAMPAIGN_MAX_VICTIMS + 5)]
    attack = [send(f"vic{i}", f"2026-07-16T11:0{i}:00.000Z", f"91.91.{i}.1")
              for i in range(3)]
    signals = compute_user_signals(load_logs(log_csv(_broad_background() + carrier + attack)))
    assert all(
        signals.get(f"emp{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(CAMPAIGN_MAX_VICTIMS + 5)
    )
    for i in range(3):
        assert signals[f"vic{i}@example.edu"]["signals"]["ip_mfa_campaign"] >= 1


def test_broad_campaign_requires_users_within_24h_window(log_csv):
    # 3 users enrolled from 55.44 but spread across 3+ days: NOT a campaign
    spread = [
        _enroll_row(f"slow{i}@example.edu", f"2026-07-{10 + 2 * i:02d}T10:00:00.000Z",
                    f"55.44.{i}.9")
        for i in range(3)
    ]
    # 3 users enrolled from 66.77 within the same hour: campaign
    burst = [
        _enroll_row(f"fast{i}@example.edu", f"2026-07-15T10:{i:02d}:00.000Z",
                    f"66.77.{i}.9")
        for i in range(3)
    ]
    signals = compute_user_signals(load_logs(log_csv(_broad_background() + spread + burst)))
    assert all(
        signals.get(f"slow{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(3)
    )
    for i in range(3):
        assert signals[f"fast{i}@example.edu"]["signals"]["ip_mfa_campaign"] == 1


def test_broad_campaign_flags_all_members_of_qualified_block(log_csv):
    """Once a block is a confirmed campaign, EVERY identifiable user active
    from it is flagged — even a clean successful login (the attacker using a
    compromised password). This is what catches victims like Warren whose only
    events in a thinned export are ordinary logins from the attack block."""
    burst = [
        _enroll_row(f"fast{i}@example.edu", f"2026-07-15T10:{i:02d}:00.000Z",
                    f"66.77.{i}.9")
        for i in range(3)
    ]
    extras = [
        {"actor.alternate_id": "warren@example.edu",  # clean login only
         "timestamp": "2026-07-15T11:30:00.000Z",
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "client.ip_address": "66.77.8.9", "client.geographical_context.city": ""},
        {"actor.alternate_id": "unknown@example.edu", "actor.display_name": "unknown",
         "timestamp": "2026-07-15T11:40:00.000Z",
         "event_type": "user.session.start", "outcome.result": "FAILURE",
         "client.ip_address": "66.77.8.7", "client.geographical_context.city": ""},
    ]
    signals = compute_user_signals(load_logs(log_csv(_broad_background() + burst + extras)))
    assert signals["warren@example.edu"]["signals"]["ip_mfa_campaign"] >= 1  # membership
    assert signals.get("unknown@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0


def test_broad_campaign_requires_datacenter_block(log_csv):
    """A campaign block must be hosting/datacenter space (IPs geolocate with no
    city), not a residential/mobile carrier where employees legitimately live.
    35.33 (AWS) is blank-city; carrier blocks resolve to real cities."""
    def send(user, ts, ip, city):
        return {"actor.type": "SystemPrincipal", "actor.display_name": user,
                "actor.alternate_id": "system@okta",
                "event_type": "system.sms.send_factor_verify_message",
                "timestamp": ts, "client.ip_address": ip,
                "client.geographical_context.city": city,
                "target0.type": "User", "target0.display_name": user,
                "target0.alternate_id": f"{user}@example.edu"}
    aws = [send(f"vic{i}", f"2026-07-15T10:0{i}:00.000Z", f"35.33.{i}.9", "")
           for i in range(3)]
    carrier = [send(f"emp{i}", f"2026-07-15T11:0{i}:00.000Z", f"73.99.{i}.9", "Washington")
               for i in range(3)]
    signals = compute_user_signals(load_logs(log_csv(_broad_background() + aws + carrier)))
    for i in range(3):
        assert signals[f"vic{i}@example.edu"]["signals"]["ip_mfa_campaign"] >= 1  # AWS
    assert all(  # residential carrier: not a campaign
        signals.get(f"emp{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(3)
    )


def test_broad_campaign_member_cap_drops_carrier_blocks(log_csv):
    """The carrier cap now counts total members, not just factor recipients:
    a qualifying block with more than CAMPAIGN_MAX_VICTIMS members is carrier
    infrastructure and is dropped."""
    from okta_agents.prefilter import CAMPAIGN_MAX_VICTIMS
    # attack: 3 enroll users + a few login-only members, under the cap
    attack = [_enroll_row(f"vic{i}@example.edu", f"2026-07-15T10:{i:02d}:00.000Z",
                          f"66.77.{i}.9") for i in range(3)]
    # carrier: 3 enroll users qualify it, but many login-only members exceed cap
    carrier = [_enroll_row(f"c{i}@example.edu", f"2026-07-16T10:{i:02d}:00.000Z",
                           f"90.90.{i}.9") for i in range(3)]
    carrier += [{"actor.alternate_id": f"emp{i}@example.edu",
                 "timestamp": "2026-07-16T12:00:00.000Z",
                 "event_type": "user.session.start", "outcome.result": "SUCCESS",
                 "client.ip_address": f"90.90.{i}.5",
                 "client.geographical_context.city": ""}
                for i in range(CAMPAIGN_MAX_VICTIMS + 2)]
    signals = compute_user_signals(load_logs(log_csv(_broad_background() + attack + carrier)))
    assert signals["vic0@example.edu"]["signals"]["ip_mfa_campaign"] >= 1
    assert all(
        signals.get(f"emp{i}@example.edu", {}).get("signals", {}).get("ip_mfa_campaign", 0) == 0
        for i in range(CAMPAIGN_MAX_VICTIMS + 2)
    )


def test_system_attributed_factor_sends_reattributed_to_target(log_csv):
    """Okta logs SMS/push factor sends with actor='Okta System'; the victim is
    in target0. load_logs must re-attribute them to the target user."""
    rows = [
        {"actor.type": "SystemPrincipal", "actor.display_name": "Okta System",
         "actor.alternate_id": "system@okta",
         "event_type": "system.sms.send_factor_verify_message",
         "timestamp": _t(5, 0), "client.ip_address": "35.33.1.1",
         "target0.type": "User", "target0.display_name": "Ernest Coleman",
         "target0.alternate_id": "ernest.coleman@example.edu"},
    ]
    df = load_logs(log_csv(rows))
    assert len(df) == 1
    assert df.iloc[0]["actor.alternate_id"] == "ernest.coleman@example.edu"
    assert df.iloc[0]["actor.display_name"] == "Ernest Coleman"
    assert df.iloc[0]["client.ip_address"] == "35.33.1.1"  # send origin preserved


def _sms(target, ts, ip="35.33.5.5"):
    return {"actor.type": "SystemPrincipal", "actor.display_name": "Okta System",
            "actor.alternate_id": "system@okta",
            "event_type": "system.sms.send_factor_verify_message",
            "timestamp": ts, "client.ip_address": ip,
            "target0.type": "User", "target0.display_name": target.title(),
            "target0.alternate_id": f"{target}@example.edu"}


def test_reattributed_sms_campaign_flags_target_victims(log_csv):
    """Real 35.33 shape: a push bomb qualifies the block, and SMS factor sends
    (system-attributed) count toward each target victim once re-attributed."""
    rows = (
        # push bomb on one user qualifies the narrow block
        [{"actor.alternate_id": "sherrod@example.edu", "timestamp": _t(6, i),
          "event_type": "system.push.send_factor_verify_push",
          "client.ip_address": "35.33.1.1"} for i in range(11)]
        # SMS sends to two other victims, system-attributed
        + [_sms("ernest", _t(6, i)) for i in range(9)]
        + [_sms("donna", _t(7, i)) for i in range(4)]
    )
    signals = compute_user_signals(load_logs(log_csv(rows)))
    assert signals["sherrod@example.edu"]["signals"]["ip_mfa_campaign"] == 11
    assert signals["ernest@example.edu"]["signals"]["ip_mfa_campaign"] == 9
    assert signals["donna@example.edu"]["signals"]["ip_mfa_campaign"] == 4


def test_events_carry_app_from_target_display_name(log_csv):
    rows = [
        {"actor.alternate_id": "user@example.edu", "timestamp": _t(12, 0),
         "event_type": "user.session.start", "outcome.result": "FAILURE"},
        {"actor.alternate_id": "user@example.edu", "timestamp": _t(12, 1),
         "event_type": "user.authentication.sso", "outcome.result": "SUCCESS",
         "target0.display_name": "Workday"},
    ]
    df = load_logs(log_csv(rows))
    cases = build_cases(df, compute_user_signals(df), max_cases=1, max_events=75)
    assert cases[0].events[-1].app == "Workday"
    assert cases[0].events[0].app == ""


def _prep(df):
    """Mimic load_logs parsing for in-memory frames."""
    import pandas as pd

    df = df.copy()
    df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df
