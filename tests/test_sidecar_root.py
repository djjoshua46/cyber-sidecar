import httpx

def test_sidecar_root_health():
    # runner is on the docker network, so it can reach the service by name
    r = httpx.get("http://sidecar:8080/")
    assert r.status_code == 200
    assert r.json().get("ok") is True
