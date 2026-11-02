import pytest
from mitigation import SandboxHosts
from capture import process_query
from storage import EventStore


def test_preview_is_opt_in_deduplicated_and_restorable(tmp_path):
    preview = SandboxHosts(tmp_path / "sandbox")
    store = EventStore(tmp_path / "events.sqlite3")
    query = {
        "domain": "abcdefghijklmnopqrstuvwxyz012345.api.lab.example.test",
        "source_ip": "192.0.2.1",
        "qtype": "TXT",
    }
    assert process_query(query, store)["action"] == "observe-only"
    assert not preview.path.exists()
    assert (
        process_query(query, store, sandbox=preview)["action"] == "sandbox-preview-only"
    )
    preview.add(query["domain"])
    assert preview.path.read_text().count(query["domain"]) == 1
    preview.restore()
    assert preview.path.read_text() == ""


def test_newline_injection_rejected_before_file_changes(tmp_path):
    preview = SandboxHosts(tmp_path / "sandbox")
    with pytest.raises(ValueError):
        preview.add("bad.test\n127.0.0.1 victim.test")
    assert not preview.path.exists()
