"""Choose one explicit workspace across source, root EXE and release subfolders."""
import json
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4


def data_directory(explicit=None):
    if explicit:
        return Path(explicit).expanduser().resolve()
    pointer = Path.home() / ".autominer" / "workspace.json"
    if pointer.is_file():
        result = Path(json.loads(pointer.read_text(encoding="utf-8"))["data_directory"])
        if not result.is_absolute() or not (result / "autominer.db").is_file():
            raise RuntimeError("已登记的数据位置不可用，停止启动；请恢复工作库或明确指定数据目录")
        return result.resolve()
    anchor = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
    for folder in (anchor, *anchor.parents):
        config = folder / "autominer.workspace.json"
        if config.is_file():
            value = json.loads(config.read_text(encoding="utf-8"))["data_directory"]
            result = Path(value).expanduser()
            return (result if result.is_absolute() else folder / result).resolve()
    # Avoid MSIX/AppData virtualization. All installed builds share this fallback.
    return (Path.home() / "AutoMinerData").resolve()


def validate_existing(directory):
    database = directory / "autominer.db"
    identity = directory / "storage.json"
    if identity.exists() and not database.is_file():
        raise RuntimeError("工作库已登记但数据库缺失，停止启动；请恢复备份，不能新建空库覆盖历史")
    if not database.exists():
        return
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        if connection.execute("pragma integrity_check").fetchall() != [("ok",)]:
            raise RuntimeError("数据库完整性检查失败，停止启动；请从备份恢复")
        secret = connection.execute("select 1 from records where kind in ('account','model') limit 1").fetchone()
        if secret and not (directory / "credential-key.dpapi").is_file():
            raise RuntimeError("已有账号或模型配置但保护密钥缺失，停止启动；不能生成新密钥")


def identify(directory):
    marker = directory / "storage.json"
    if marker.exists():
        identity = json.loads(marker.read_text(encoding="utf-8"))
    else:
        identity = {"id": uuid4().hex, "database": "autominer.db"}
        with marker.open("x", encoding="utf-8") as handle:
            json.dump(identity, handle, ensure_ascii=False, indent=2)
    return identity["id"]


def backup_existing(directory):
    database = directory / "autominer.db"
    if not database.exists():
        return
    from datetime import datetime
    import shutil
    destination = directory / "backups" / ("startup-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:6])
    destination.mkdir(parents=True)
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as source, sqlite3.connect(destination / "autominer.db") as target:
        source.backup(target)
    for name in ("credential-key.dpapi", "settings.json", "storage.json"):
        if (directory / name).exists():
            shutil.copy2(directory / name, destination / name)


def remember(directory):
    pointer = Path.home() / ".autominer" / "workspace.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    content = {"data_directory": str(directory.resolve())}
    if pointer.exists():
        if json.loads(pointer.read_text(encoding="utf-8")) != content:
            raise RuntimeError("已登记其他工作库，不能自动切换数据位置")
        return
    with pointer.open("x", encoding="utf-8") as handle:
        json.dump(content, handle, ensure_ascii=False, indent=2)
