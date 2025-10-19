import pytest

# If Flask isn't installed in the environment, skip these integration tests.
pytest.importorskip("flask")

from src import server


def test_full_flow_init_register_auth_cast_tally_verify():
    app = server.app
    client = app.test_client()

    # Initialize
    rv = client.post("/init", json={})
    assert rv.status_code == 200

    # Register a voter
    rv = client.post("/register", json={"voter_id": "alice@example.org"})
    assert rv.status_code == 200

    # Authenticate
    rv = client.post("/auth", json={"voter_id": "alice@example.org"})
    assert rv.status_code == 200
    data = rv.get_json()
    token = data.get("token")
    mac = data.get("mac")
    assert isinstance(token, str) and isinstance(mac, str)

    # Cast a ballot using /cast
    ballot = {"default": "Alice"}
    rv = client.post(
        "/cast",
        json={
            "voter_id": "alice@example.org",
            "ballot": ballot,
            "token": token,
            "mac": mac,
        },
    )
    assert rv.status_code == 201

    # Also post a raw ballot for tally endpoint
    rv = client.post("/ballot", json={"choice": "Alice"})
    assert rv.status_code == 201

    # Tally raw ballots
    rv = client.post("/tally", json={})
    assert rv.status_code == 200
    data = rv.get_json()
    assert "tally" in data and "hash" in data

    # Verify hash
    pub_hash = data["hash"]
    rv = client.post("/verify", json={"hash": pub_hash})
    assert rv.status_code == 200
    v = rv.get_json()
    assert v.get("ok") is True
