import json

import pytest

from capture import main
from storage import EventStore


def test_demo_has_deterministic_scores_without_live_capture(
    tmp_path, monkeypatch, capsys
):
    import scapy.sendrecv
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "The offline demo must not open a connection or sniff traffic"
        )

    monkeypatch.setattr(scapy.sendrecv, "sniff", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    database = tmp_path / "events.sqlite3"
    monkeypatch.setattr(
        "sys.argv", ["capture.py", "--demo", "--database", str(database)]
    )
    main()
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["score"] for row in rows[:-1]] == [0, 0, 80, 100, 60]
    assert all(row["action"] == "observe-only" for row in rows[:-1])
    assert rows[-1] == {"summary": {"processed": 5, "skipped": 0}}
    assert EventStore(database).snapshot()[1]["total"] == 5


def test_live_mode_requires_explicit_interface(monkeypatch):
    monkeypatch.setattr("sys.argv", ["capture.py", "--live"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
