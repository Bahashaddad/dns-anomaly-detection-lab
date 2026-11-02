from concurrent.futures import ThreadPoolExecutor
from capture import process_query
from storage import EventStore
from dashboard import create_app


def test_bounded_concurrent_storage(tmp_path):
    store = EventStore(tmp_path / "events.sqlite3", max_events=5)

    def write(i):
        return process_query(
            {"domain": f"sample{i}.example.test", "source_ip": "192.0.2.1"}, store
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(20)))
    events, summary = store.snapshot()
    assert len(events) == summary["total"] == 5
    assert all(e["action"] == "observe-only" for e in events)


def test_dashboard_escapes_stored_data_and_rejects_remote_clients(tmp_path):
    path = tmp_path / "events.sqlite3"
    store = EventStore(path)
    event = process_query({"domain": "example.test", "source_ip": "192.0.2.1"}, store)
    event["domain"] = "<script>alert(1)</script>{{7*7}}"
    store.append(event)
    app = create_app(path)
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data
    assert b"{{7*7}}" in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        client.get("/", environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code
        == 403
    )
