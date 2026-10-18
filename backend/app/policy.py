"""Fail-closed URL policy and DNS-pinned transport; no environment proxy support."""

import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from urllib.parse import unquote, urljoin, urlsplit


class Denied(ValueError):
    pass


def canonical_path(path):
    path = path or "/"
    if not path.startswith("/") or re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise Denied("无效路径")
    decoded = path
    for _ in range(5):
        try:
            nxt = unquote(decoded, errors="strict")
        except UnicodeError as exc:
            raise Denied("路径包含无效 UTF-8 编码") from exc
        if nxt == decoded:
            break
        decoded = nxt
    if (
        "%" in decoded
        or "\\" in decoded
        or any(ord(c) < 32 for c in decoded)
        or "//" in decoded
        or any(p in (".", "..") for p in decoded.split("/"))
    ):
        raise Denied("路径编码或规范化不明确")
    return decoded


def under(path, prefix):
    return (
        prefix == "/"
        or path == prefix.rstrip("/")
        or path.startswith(prefix.rstrip("/") + "/")
    )


def check_url(target, url):
    try:
        u = urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        host = (u.hostname or "").encode("idna").decode().lower()
    except (ValueError, UnicodeError) as e:
        raise Denied("无效 URL") from e
    if u.username or u.password or u.fragment or u.scheme not in ("http", "https"):
        raise Denied("不允许的 URL 格式")
    if (u.scheme, host, port) != (target["scheme"], target["host"], target["port"]):
        raise Denied("主机、协议或端口超出授权")
    if any(ord(c) < 33 for c in url) or "\\" in url:
        raise Denied("URL 包含不安全字符")
    path = canonical_path(u.path)
    if not any(under(path, p) for p in target["paths"]) or any(
        under(path, p) for p in target["deny_paths"]
    ):
        raise Denied("路径超出授权")
    return u


def resolve(target):
    addresses = sorted(
        {
            x[4][0]
            for x in socket.getaddrinfo(
                target["host"], target["port"], type=socket.SOCK_STREAM
            )
        }
    )
    if not addresses:
        raise Denied("DNS 无结果")
    bindings = target.get("bound_ips", [])
    if target["kind"] == "local":
        controls = {int(p) for p in os.getenv("CONTROL_PORTS", "8000").split(",") if p}
        if (
            os.getenv("DESKTOP_LOCAL_TARGETS") != "1"
            or target["host"] not in ("localhost", "127.0.0.1", "::1")
            or target["scheme"] != "http"
        ):
            raise Denied("本机目标仅在 Windows 原生运行模式开放")
        if target["port"] < 1024 or target["port"] in controls | {
            2375,
            2376,
            3306,
            5432,
            6379,
        }:
            raise Denied("禁止测试系统端口、数据库端口或 AutoMiner 自身服务")
        if any(
            a not in ("127.0.0.1", "::1") or (bindings and a not in bindings)
            for a in addresses
        ):
            raise Denied("本机目标必须始终解析到授权的标准回环地址")
        return addresses
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or getattr(ip, "ipv4_mapped", None)
        ):
            raise Denied("禁止的网络地址")
        if bindings and address not in bindings:
            raise Denied("DNS 地址与授权绑定不一致")
        if target["kind"] == "lab" and ip.is_global:
            raise Denied(
                "首版靶场仅允许配置的隔离私网实例，不能以靶场声明绕过公网所有权验证"
            )
        if not ip.is_global and (target["kind"] != "lab" or address not in bindings):
            raise Denied("私网仅允许明确绑定的靶场实例")
        if not ip.is_global:
            networks = [
                ipaddress.ip_network(n.strip())
                for n in os.getenv("LAB_NETWORK_CIDRS", "172.30.10.0/24").split(",")
            ]
            allowed = [
                n
                for n in networks
                if ip in n
                and ip
                not in (n.network_address, n.broadcast_address, n.network_address + 1)
            ]
            if not allowed or target["port"] in (
                22,
                135,
                139,
                445,
                2375,
                2376,
                3306,
                5432,
                6379,
                8000,
            ):
                raise Denied("不属于配置的靶场网络，或属于管理端口")
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address):
        super().__init__(host, port, timeout=8, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class LoopbackHTTP(http.client.HTTPConnection):
    """Try only prevalidated loopback addresses, before sending any HTTP bytes."""

    def __init__(self, host, port, addresses):
        super().__init__(host, port, timeout=8)
        self.addresses = addresses

    def connect(self):
        last = None
        for address in self.addresses:
            try:
                self.sock = socket.create_connection((address, self.port), self.timeout)
                return
            except OSError as exc:
                last = exc
        raise last or ConnectionError("本机应用不可达")


def request(target, url, headers=None, before_send=None, *, probe_label=None):
    origins = {"baseline": None, "probe_a": "https://autominer-a.invalid", "probe_b": "https://autominer-b.invalid"}
    if probe_label is not None and probe_label not in origins:
        raise Denied("不允许的固定验证探针")
    started = time.monotonic()
    u = check_url(target, url)
    addresses = resolve(target)
    address = addresses[0]
    if target["kind"] == "local":
        conn = LoopbackHTTP(target["host"], target["port"], addresses)
    elif u.scheme == "https":
        conn = PinnedHTTPS(target["host"], target["port"], address)
    else:
        conn = http.client.HTTPConnection(address, target["port"], timeout=8)
    host = target["host"]
    host = f"[{host}]" if ":" in host else host
    safe_headers = {
        "Host": f"{host}:{target['port']}",
        "User-Agent": "AutoMiner/0.1 authorized-test",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    for key, value in (headers or {}).items():
        if (
            key.lower() not in ("authorization", "cookie", "x-test-account")
            or "\r" in value
            or "\n" in value
        ):
            raise Denied("不允许的账号请求头")
        safe_headers[key] = value
    if probe_label is not None and origins[probe_label]:
        safe_headers["Origin"] = origins[probe_label]
    try:
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        if before_send:
            before_send()
        conn.request("GET", path, headers=safe_headers)
        response = conn.getresponse()
        chunks, size = [], 0
        while size < 65537:
            remaining = 10 - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("响应总时限已到")
            if conn.sock:
                conn.sock.settimeout(min(remaining, 8))
            chunk = response.read1(min(8192, 65537 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
        result = {
            "status": response.status,
            "headers": dict(response.getheaders()),
            "body": body[:65536].decode("utf-8", errors="replace"),
            "body_bytes": len(body[:65536]),
            "request_headers": safe_headers,
            "request_body": "",
            "truncated": len(body) > 65536,
            "address": address,
        }
        # Redirects are never followed. Record only an in-scope location.
        location = response.getheader("Location")
        if location:
            try:
                check_url(target, urljoin(url, location))
            except Denied:
                result["headers"] = {
                    k: v
                    for k, v in result["headers"].items()
                    if k.lower() != "location"
                }
                result["redirect_blocked"] = True
        return result
    finally:
        conn.close()
