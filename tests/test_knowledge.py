import json
import subprocess
import sys
from pathlib import Path

import pytest

from portpatrol import knowledge
from portpatrol.defaults import DEFAULT_ENTRIES, TOP_PORTS

REQUIRED_KEYS = {"port", "protocol", "service", "risk", "banner_first", "probe", "match", "advice", "kev_hints"}
RISKS = {"critical", "high", "medium", "info", "unknown"}

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATE_SCRIPT = REPO_ROOT / "scripts" / "generate_kb.py"


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


def test_packaged_kb_matches_defaults():
    packaged = json.loads(knowledge.PACKAGE_KB.read_text(encoding="utf-8"))
    assert packaged == DEFAULT_ENTRIES


def test_generate_kb_script_matches_packaged_file(tmp_path):
    out = tmp_path / "knowledge_base.json"
    subprocess.run([sys.executable, str(GENERATE_SCRIPT), str(out)],
                   check=True, cwd=str(REPO_ROOT))
    assert out.read_bytes() == knowledge.PACKAGE_KB.read_bytes()


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


def test_load_knowledge_base_invalid_risk_warns_and_downgrades(tmp_path, capsys):
    user_kb = tmp_path / "knowledge_base.json"
    user_kb.write_text(json.dumps([
        {"port": 9999, "protocol": "tcp", "service": "testsvc", "risk": "extreme",
         "banner_first": False, "probe": None, "match": [], "advice": "test advice",
         "kev_hints": []}
    ]), encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=user_kb)
    assert kb[9999]["risk"] == "unknown"
    err = capsys.readouterr().err
    assert "invalid risk" in err
    assert "'extreme'" in err
    assert "9999" in err


def test_load_knowledge_base_missing_risk_warns_and_downgrades(tmp_path, capsys):
    user_kb = tmp_path / "knowledge_base.json"
    user_kb.write_text(json.dumps([
        {"port": 9999, "protocol": "tcp", "service": "testsvc",
         "banner_first": False, "probe": None, "match": [], "advice": "test advice",
         "kev_hints": []}
    ]), encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=user_kb)
    assert kb[9999]["risk"] == "unknown"
    err = capsys.readouterr().err
    assert "missing" in err and "risk" in err


def test_load_knowledge_base_valid_risk_is_silent(tmp_path, capsys):
    user_kb = tmp_path / "knowledge_base.json"
    user_kb.write_text(json.dumps([
        {"port": 9999, "protocol": "tcp", "service": "testsvc", "risk": "high",
         "banner_first": False, "probe": None, "match": [], "advice": "test advice",
         "kev_hints": []}
    ]), encoding="utf-8")
    knowledge.load_knowledge_base(user_path=user_kb)
    assert capsys.readouterr().err == ""


def test_classify_port_invalid_risk_returns_unknown():
    kb = {23: {"port": 23, "service": "telnet", "risk": "extreme"}}
    assert knowledge.classify_port(kb, 23) == "unknown"
    kb = {23: {"port": 23, "service": "telnet"}}
    assert knowledge.classify_port(kb, 23) == "unknown"
    assert knowledge.classify_port(kb, 40000, service="notaservice") == "unknown"


def test_service_index_maps_names_to_entries():
    kb = knowledge.load_knowledge_base()
    idx = knowledge.service_index(kb)
    assert idx["ssh"]["port"] == 22


def test_parse_port_spec_list():
    assert knowledge.parse_port_spec("80,443", TOP_PORTS) == [80, 443]


def test_parse_port_spec_range():
    assert knowledge.parse_port_spec("8000-8003", TOP_PORTS) == [8000, 8001, 8002, 8003]


def test_parse_port_spec_mixed_dedup_sorted():
    assert knowledge.parse_port_spec("443,80,8000-8001,80", TOP_PORTS) == [80, 443, 8000, 8001]


def test_parse_port_spec_top50():
    assert knowledge.parse_port_spec("top50", TOP_PORTS) == TOP_PORTS[:50]


def test_parse_port_spec_top1000_covers_well_known():
    ports = knowledge.parse_port_spec("top1000", TOP_PORTS)
    for known in (22, 6379, 27017):
        assert known in ports
    assert max(ports) >= 27017


def test_parse_port_spec_all_length():
    assert len(knowledge.parse_port_spec("all", TOP_PORTS)) == 65535


def test_parse_port_spec_invalid():
    with pytest.raises(ValueError):
        knowledge.parse_port_spec("0", TOP_PORTS)
    with pytest.raises(ValueError):
        knowledge.parse_port_spec("80-", TOP_PORTS)


def test_classify_port_by_port_entry():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 23) == "critical"
    assert knowledge.classify_port(kb, 22) == "info"


def test_classify_port_by_service_match():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 12345, service="redis") == "critical"


def test_classify_port_unknown():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 40000, service="notaservice") == "unknown"


def test_adjust_risk_loopback_downgrades_one_level():
    assert knowledge.adjust_risk_for_exposure("critical", "loopback") == "high"
    assert knowledge.adjust_risk_for_exposure("high", "loopback") == "medium"
    assert knowledge.adjust_risk_for_exposure("medium", "loopback") == "info"
    assert knowledge.adjust_risk_for_exposure("info", "loopback") == "info"
    assert knowledge.adjust_risk_for_exposure("unknown", "loopback") == "unknown"


def test_adjust_risk_interface_or_unknown_exposure_unchanged():
    assert knowledge.adjust_risk_for_exposure("critical", "interface") == "critical"
    assert knowledge.adjust_risk_for_exposure("medium", "interface") == "medium"
    assert knowledge.adjust_risk_for_exposure("high", "unknown") == "high"
