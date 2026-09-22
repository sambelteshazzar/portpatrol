from portpatrol import diff


def _finding(port, service="ssh", version=None, risk="info"):
    return {"port": port, "service": service, "version": version, "risk": risk}


def test_load_state_missing_returns_none(tmp_path):
    assert diff.load_state(tmp_path / "state.json") is None


def test_load_state_invalid_returns_none(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not json", encoding="utf-8")
    assert diff.load_state(p) is None


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    diff.save_state(p, [_finding(22)])
    state = diff.load_state(p)
    assert state["open"] == [{"port": 22, "service": "ssh", "version": None, "risk": "info"}]
    assert state["version"] == 1


def test_save_state_slims_extra_keys(tmp_path):
    p = tmp_path / "state.json"
    diff.save_state(p, [{"port": 443, "service": "https", "version": "1.2", "risk": "info",
                         "cves": ["CVE-1"], "product": "nginx"}])
    stored = diff.load_state(p)["open"][0]
    assert set(stored) == {"port", "service", "version", "risk"}


def test_load_allowlist_missing_returns_empty_set(tmp_path):
    assert diff.load_allowlist(tmp_path / "allowlist.json") == set()


def test_load_allowlist_parses_int_list(tmp_path):
    p = tmp_path / "allowlist.json"
    p.write_text("[22, 631]", encoding="utf-8")
    assert diff.load_allowlist(p) == {22, 631}


def test_compute_changes_identical_is_empty():
    curr = [_finding(22)]
    changes = diff.compute_changes([_finding(22)], curr, set())
    assert changes == {"new": [], "removed": [], "changed": []}


def test_compute_changes_detects_new_port():
    changes = diff.compute_changes([], [_finding(8080, service="http-proxy", risk="medium")], set())
    assert [f["port"] for f in changes["new"]] == [8080]
    assert changes["new"][0]["risk"] == "medium"


def test_compute_changes_allowlist_suppresses_new():
    changes = diff.compute_changes([], [_finding(631)], {631})
    assert changes["new"] == []


def test_compute_changes_detects_removed_port():
    changes = diff.compute_changes([_finding(22), _finding(80)], [_finding(22)], set())
    assert [f["port"] for f in changes["removed"]] == [80]


def test_compute_changes_detects_service_or_version_change():
    prev = [_finding(22, service="ssh", version="OpenSSH_8.9")]
    curr = [_finding(22, service="ssh", version="OpenSSH_9.6")]
    changes = diff.compute_changes(prev, curr, set())
    assert changes["changed"] == [
        {"port": 22,
         "from": {"service": "ssh", "version": "OpenSSH_8.9"},
         "to": {"service": "ssh", "version": "OpenSSH_9.6"}}
    ]


def test_compute_changes_allowlist_does_not_hide_removals():
    changes = diff.compute_changes([_finding(631)], [], {631})
    assert [f["port"] for f in changes["removed"]] == [631]


def test_has_changes():
    empty = {"new": [], "removed": [], "changed": []}
    assert diff.has_changes(empty) is False
    assert diff.has_changes({"new": [_finding(80)], "removed": [], "changed": []}) is True


def test_changes_message_lists_new_with_risk():
    msg = diff.changes_message({"new": [_finding(8080, risk="medium")],
                                "removed": [], "changed": []})
    assert msg.startswith("🆕")
    assert "8080" in msg
    assert "medium" in msg


def test_changes_message_critical_new_leads_with_siren():
    msg = diff.changes_message({"new": [_finding(6379, service="redis", risk="critical")],
                                "removed": [], "changed": []})
    assert msg.startswith("🚨")


def test_changes_message_includes_removed_and_changed():
    msg = diff.changes_message({"new": [],
                                "removed": [_finding(80)],
                                "changed": [{"port": 22,
                                             "from": {"service": "ssh", "version": "8.9"},
                                             "to": {"service": "ssh", "version": "9.6"}}]})
    assert "1 removed" in msg
    assert "80" in msg
    assert "1 changed" in msg
    assert "22" in msg


def test_changes_message_empty_is_all_clear():
    msg = diff.changes_message({"new": [], "removed": [], "changed": []})
    assert msg.startswith("✅")
