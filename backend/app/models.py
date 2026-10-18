"""Model endpoints are operator-allowlisted, separate from scanning targets."""

import http.client
import ipaddress
import json
import socket
from urllib.parse import urlsplit

from .policy import Denied, PinnedHTTPS, resolve
from .security import decrypt


def check_provider(model):
    from .model_management import provider_settings

    name = "MODEL_LOCAL_BASE_URLS" if model["local"] else "MODEL_CLOUD_BASE_URLS"
    allowed = [
        u.strip().rstrip("/") for u in provider_settings()[name].split(",") if u.strip()
    ]
    if model["base_url"].rstrip("/") not in allowed:
        raise Denied("模型地址未列入运营者配置的 " + name)


def completion(model, prompt):
    check_provider(model)
    url = urlsplit(model["base_url"])
    port = url.port or (443 if url.scheme == "https" else 80)
    host = url.hostname
    if model["local"]:
        addresses = sorted(
            {r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        )
        if not addresses or any(
            ipaddress.ip_address(a).is_link_local
            or ipaddress.ip_address(a).is_unspecified
            or ipaddress.ip_address(a).is_multicast
            for a in addresses
        ):
            raise Denied("本地模型地址无效")
    else:
        addresses = resolve(
            {"kind": "owned", "host": host, "port": port, "bound_ips": []}
        )
    connection = (
        PinnedHTTPS(host, port, addresses[0])
        if url.scheme == "https"
        else http.client.HTTPConnection(addresses[0], port, timeout=30)
    )
    authority = "[" + host + "]" if ":" in host else host
    payload = json.dumps(
        {
            "model": model["model"],
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": model["max_output_tokens"],
            "response_format": {"type": "json_object"},
        }
    ).encode()
    try:
        connection.request(
            "POST",
            url.path.rstrip("/") + "/chat/completions",
            body=payload,
            headers={
                "Host": f"{authority}:{port}",
                "Content-Type": "application/json",
                "Authorization": "Bearer " + decrypt(model["encrypted_key"]),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(1_000_001)
        if response.status != 200 or len(body) > 1_000_000:
            raise Denied("模型响应失败、重定向或超出大小限制")
        result = json.loads(body)
        return json.loads(result["choices"][0]["message"]["content"])
    finally:
        connection.close()
