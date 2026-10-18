import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from desktop.launcher import Bridge, allocate_ports, configure
from desktop.windows import protect


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI")
def test_dpapi_key_survives_restart(tmp_path):
    directory, first = configure(tmp_path)
    _, second = configure(tmp_path)
    assert first["ENCRYPTION_KEY"] == second["ENCRYPTION_KEY"]
    assert first["APP_TOKEN"] != second["APP_TOKEN"]
    assert (
        first["ENCRYPTION_KEY"].encode()
        not in (directory / "credential-key.dpapi").read_bytes()
    )
    assert protect(protect(b"synthetic-secret"), decrypt=True) == b"synthetic-secret"


def test_distinct_dynamic_ports():
    ports = allocate_ports()
    assert len(set(ports)) == 3
    assert all(p >= 1024 for p in ports)


def test_bridge_only_trusts_own_origin():
    class Runtime:
        origin = "http://127.0.0.1:49100"
        environment = {"APP_TOKEN": "synthetic"}

    class Window:
        url = "http://127.0.0.1:49100/"

        def get_current_url(self):
            return self.url

    bridge = Bridge(Runtime())
    bridge._window = Window()
    assert bridge.session_token() == "synthetic"
    bridge._window.url = "http://localhost:5177/"
    with pytest.raises(PermissionError):
        bridge.session_token()
