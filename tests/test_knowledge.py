import json

from portpatrol import knowledge
from portpatrol.defaults import DEFAULT_ENTRIES, TOP_PORTS

REQUIRED_KEYS = {"port", "protocol", "service", "risk", "banner_first", "probe", "match", "advice", "kev_hints"}
RISKS = {"critical", "high", "medium", "info", "unknown"}


def test_default_entries_validate_against_schema():
    assert len(DEFAULT_ENTRIES) >= 40
    for entry in DEFAULT_ENTRIES:
        assert REQUIRED_KEYS <= set(entry), entry["port"]
        assert entry["protocol"] == "tcp"
        assert entry["risk"] in RISKS, entry["port"]
        assert isinstance(entry["port"], int) and 1 <= entry["port"] <= 65535
        assert isinstance(entry["match"], list)
        assert isinstance(entry["kev_hints"], list)
        assert isinstance(entry["advice"], str) and entry["advice"]


def test_top_ports_list_has_100_unique_ports():
    assert len(TOP_PORTS) == 100
    assert len(set(TOP_PORTS)) == 100
    for known in (80, 443, 22, 3306, 3389, 5900, 6379, 27017):
        assert known in TOP_PORTS


def test_load_knowledge_base_uses_user_override(tmp_path):
    user_kb = tmp_path / "knowledge_base.json"
    user_kb.write_text(json.dumps([
        {"port": 9999, "protocol": "tcp", "service": "testsvc", "risk": "high",
         "banner_first": False, "probe": None, "match": [], "advice": "test advice",
         "kev_hints": []}
    ]), encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=user_kb)
    assert kb[9999]["risk"] == "high"


def test_load_knowledge_base_invalid_json_falls_back(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=bad)
    assert 22 in kb


def test_service_index_maps_names_to_entries():
    kb = knowledge.load_knowledge_base()
    idx = knowledge.service_index(kb)
    assert idx["ssh"]["port"] == 22
