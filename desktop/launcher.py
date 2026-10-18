"""Windows desktop entry point; service imports happen only after runtime configuration."""

import argparse
import base64
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "backend"))

from desktop.windows import ChildJob, protect
from desktop.storage import data_directory, validate_existing, identify, backup_existing, remember


def configure(data_dir=None):
    directory = data_directory(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    validate_existing(directory)
    key_path = directory / "credential-key.dpapi"
    if key_path.exists():
        key = protect(key_path.read_bytes(), decrypt=True).decode()
    else:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        with key_path.open("xb") as handle:
            handle.write(protect(key.encode()))
    settings_path = directory / "settings.json"
    defaults = {
        "model_cloud_base_urls": "",
        "model_local_base_urls": "",
        "model_max_usd_per_million_tokens": 0,
    }
    if not settings_path.exists():
        settings_path.write_text(
            json.dumps(defaults, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    backup_existing(directory)
    environment = dict(os.environ)
    environment.update(
        DATABASE_URL="sqlite:///" + (directory / "autominer.db").as_posix(),
        ENCRYPTION_KEY=key,
        APP_TOKEN=secrets.token_urlsafe(32),
        INTERNAL_TOKEN=secrets.token_urlsafe(32),
        DESKTOP_LOCAL_TARGETS="1",
        FRONTEND_DIR=str(Path(getattr(sys, "_MEIPASS", ROOT)) / "frontend" / "dist"),
        MODEL_CLOUD_BASE_URLS=str(settings.get("model_cloud_base_urls", "")),
        MODEL_LOCAL_BASE_URLS=str(settings.get("model_local_base_urls", "")),
        MODEL_MAX_USD_PER_MILLION_TOKENS=str(
            settings.get("model_max_usd_per_million_tokens", 0)
        ),
    )
    # No inherited shell proxy or obsolete Docker configuration is used.
    environment.pop("SERVICE_ROLE", None)
    return directory, environment


def allocate_ports():
    sockets = []
    try:
        for _ in range(3):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


class Runtime:
    def __init__(self, data_dir=None):
        import msvcrt

        directory = data_directory(data_dir)
        directory.mkdir(parents=True, exist_ok=True)
        self.lock = (directory / "app.lock").open("a+b")
        try:
            if self.lock.tell() == 0:
                self.lock.write(b"0")
                self.lock.flush()
            self.lock.seek(0)
            msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            self.directory, self.environment = configure(directory)
        except Exception as exc:
            self.lock.close()
            raise RuntimeError(f"无法打开工作库 {directory}：{exc}") from exc
        self.remember_storage = data_dir is None
        self.processes = []
        self.logs = []
        self.job = None
        api, gateway, model = allocate_ports()
        self.origin = f"http://127.0.0.1:{api}"
        self.environment.update(
            APP_ORIGIN=self.origin,
            EXECUTION_GATEWAY_URL=f"http://127.0.0.1:{gateway}",
            MODEL_GATEWAY_URL=f"http://127.0.0.1:{model}",
            CONTROL_PORTS=",".join(map(str, (api, gateway, model, 8000))),
            AUTOMINER_DATA_DIR=str(directory),
        )
        self.ports = {"api": api, "gateway": gateway, "model": model}

    def start(self):
        import httpx

        os.environ.update(self.environment)
        from app.store import init_db, engine
        from app.service import locked, all_of, save, audit

        init_db()
        self.environment["AUTOMINER_STORAGE_ID"] = identify(self.directory)
        if self.remember_storage:
            remember(self.directory)
        os.environ["AUTOMINER_STORAGE_ID"] = self.environment["AUTOMINER_STORAGE_ID"]
        with locked() as session:
            for row in all_of(session, "job") + all_of(session, "discovery") + all_of(session, "auto_scan"):
                if row["status"] in ("queued", "running", "paused"):
                    row.update(
                        status="stopped", error="上次桌面会话已结束；不会自动重放请求"
                    )
                    for entry in row.get("requests", []):
                        if entry["state"] in ("reserved", "in_flight"):
                            entry["state"] = "interrupted"
                    save(session, row)
            for row in all_of(session, "evidence"):
                if row["state"] in ("reserved", "in_flight"):
                    row.update(state="interrupted")
                    save(session, row)
            audit(session, "desktop_started", "local")
        engine.dispose()
        self.job = ChildJob()
        for role in ("gateway", "model", "api", "worker"):
            command = (
                [sys.executable]
                if getattr(sys, "frozen", False)
                else [sys.executable, str(Path(__file__).resolve())]
            )
            env = dict(
                self.environment,
                SERVICE_ROLE=role,
                SERVICE_PORT=str(self.ports.get(role, 0)),
            )
            log = (self.directory / f"{role}.log").open("w", encoding="utf-8")
            self.logs.append(log)
            process = subprocess.Popen(
                command + ["--service", role],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            self.processes.append(process)
            self.job.add(process)
        deadline = time.monotonic() + 45
        with httpx.Client(trust_env=False, timeout=1) as client:
            for role in ("gateway", "model", "api"):
                while True:
                    if any(p.poll() is not None for p in self.processes):
                        raise RuntimeError(
                            "本地服务启动失败，请查看应用数据目录中的日志"
                        )
                    path = "/api/health" if role == "api" else "/internal/health"
                    key = "X-API-Key" if role == "api" else "X-Internal-Token"
                    token = self.environment[
                        "APP_TOKEN" if role == "api" else "INTERNAL_TOKEN"
                    ]
                    try:
                        response = client.get(
                            f"http://127.0.0.1:{self.ports[role]}" + path,
                            headers={key: token},
                        )
                        if (
                            response.status_code == 200
                            and response.json()["role"] == role
                            and response.json().get("storage_id") == self.environment["AUTOMINER_STORAGE_ID"]
                        ):
                            break
                    except (httpx.HTTPError, ValueError):
                        pass
                    if time.monotonic() > deadline:
                        raise TimeoutError("本地服务启动超时")
                    time.sleep(0.15)

    def close(self):
        if self.processes:
            try:
                import httpx

                httpx.post(
                    self.origin + "/api/emergency-stop",
                    json={},
                    headers={"X-API-Key": self.environment["APP_TOKEN"]},
                    timeout=2,
                    trust_env=False,
                )
            except Exception:
                pass
        if self.job:
            self.job.close()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in self.logs:
            log.close()
        self.processes.clear()
        if not self.lock.closed:
            self.lock.close()


class Bridge:
    def __init__(self, runtime):
        self._runtime = runtime
        self._window = None

    def session_token(self):
        current = urlsplit(self._window.get_current_url() or "")
        expected = urlsplit(self._runtime.origin)
        if (current.scheme, current.netloc) != (expected.scheme, expected.netloc):
            raise PermissionError("桌面会话只能在本地工作台读取")
        return self._runtime.environment["APP_TOKEN"]


def serve(role):
    logging.basicConfig(
        filename=str(Path(os.environ["AUTOMINER_DATA_DIR"]) / f"{role}.log"),
        encoding="utf-8",
        level=logging.INFO,
    )
    if role == "worker":
        from app.worker import main

        main()
    else:
        import uvicorn
        from app.main import app

        uvicorn.run(
            app,
            host="127.0.0.1",
            port=int(os.environ["SERVICE_PORT"]),
            log_config=None,
            access_log=False,
        )


def main():
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", choices=["api", "gateway", "model", "worker"])
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--check-storage", action="store_true")
    parser.add_argument("--data-dir")
    parser.add_argument("--result-file")
    args = parser.parse_args()
    if args.service:
        try:
            serve(args.service)
            return 0
        except Exception:
            logging.exception("Local service startup failed")
            return 1
    runtime = None
    try:
        if os.name != "nt":
            raise OSError("桌面版仅支持 Windows 10/11")
        runtime = Runtime(args.data_dir)
        runtime.start()
        if args.check_storage:
            from app.store import Session
            from app.service import all_of
            from app.security import decrypt
            with Session() as session:
                counts = {kind: len(all_of(session, kind)) for kind in ("target", "job", "evidence", "account", "model")}
                for row in all_of(session, "account"):
                    decrypt(row["encrypted_headers"])
                for row in all_of(session, "model"):
                    decrypt(row["encrypted_key"])
                hosts = sorted({row["host"] for row in all_of(session, "target")})
            result = dict(ok=True, data_directory=str(runtime.directory), storage_id=runtime.environment["AUTOMINER_STORAGE_ID"], counts=counts, hosts=hosts, credentials_decryptable=True)
            if args.result_file:
                Path(args.result_file).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            return
        if args.smoke_test:
            from desktop.smoke import check, check_persistence

            result = check(runtime)
            directory = runtime.directory
            runtime.close()
            runtime = Runtime(directory)
            runtime.start()
            check_persistence(runtime)
            result["restart_persistence"] = True
            if args.result_file:
                Path(args.result_file).write_text(json.dumps(result), encoding="utf-8")
            return
        import webview

        bridge = Bridge(runtime)
        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.settings["ALLOW_FILE_URLS"] = False
        window = webview.create_window(
            "AutoMiner · 授权安全工作台",
            runtime.origin,
            js_api=bridge,
            width=1280,
            height=860,
            min_size=(800, 600),
            background_color="#faf9f6",
        )
        bridge._window = window
        webview.start(gui="edgechromium", private_mode=True)
    except Exception as exc:
        if args.result_file:
            Path(args.result_file).write_text(
                json.dumps({"ok": False, "error": str(exc)}), encoding="utf-8"
            )
        if not args.smoke_test and not args.check_storage:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None,
                str(exc)
                + "\n请查看选定工作库目录中的 api.log、gateway.log 等日志。",
                "AutoMiner 无法启动",
                0x10,
            )
        logging.exception("Desktop startup failed")
        return 1
    finally:
        if runtime:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main() or 0)
