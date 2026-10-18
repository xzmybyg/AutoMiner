import json
from pathlib import Path
import sqlite3
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from desktop import storage


def test_root_and_release_exes_use_same_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path/"home"))
    root=tmp_path/"project";root.mkdir()
    (root/"autominer.workspace.json").write_text('{"data_directory":"data/desktop"}')
    monkeypatch.setattr(sys,"frozen",True,raising=False)
    for location in (root/"AutoMiner.exe",root/"release"/"new"/"AutoMiner.exe"):
        monkeypatch.setattr(sys,"executable",str(location))
        assert storage.data_directory() == root/"data"/"desktop"
    assert storage.data_directory(tmp_path/"explicit") == tmp_path/"explicit"


def test_source_and_exe_workspace_match(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path/"home"))
    (tmp_path/"autominer.workspace.json").write_text('{"data_directory":"data/desktop"}')
    monkeypatch.setattr(storage,"__file__",str(tmp_path/"desktop"/"storage.py"))
    monkeypatch.setattr(sys,"frozen",False,raising=False)
    assert storage.data_directory() == tmp_path/"data"/"desktop"


def test_registered_missing_or_corrupt_database_never_creates_new_key(tmp_path):
    (tmp_path/"storage.json").write_text('{"id":"existing"}')
    with pytest.raises(RuntimeError):storage.validate_existing(tmp_path)
    (tmp_path/"autominer.db").write_bytes(b"damaged database")
    with pytest.raises(sqlite3.DatabaseError):storage.validate_existing(tmp_path)
    assert not (tmp_path/"credential-key.dpapi").exists()


def test_secret_records_require_existing_key(tmp_path):
    with sqlite3.connect(tmp_path/"autominer.db") as c:
        c.execute('create table records(id text,kind text,payload text)')
        c.execute("insert into records values('a','account','{}')")
    with pytest.raises(RuntimeError):storage.validate_existing(tmp_path)
    (tmp_path/"credential-key.dpapi").write_bytes(b"synthetic-protected-key")
    storage.validate_existing(tmp_path)
    first=storage.identify(tmp_path)
    assert storage.identify(tmp_path)==first
    storage.backup_existing(tmp_path)
    backups=list((tmp_path/"backups").iterdir())
    assert len(backups)==1
    assert (backups[0]/"credential-key.dpapi").read_bytes()==b"synthetic-protected-key"
    with sqlite3.connect(backups[0]/"autominer.db") as c:assert c.execute('select count(*) from records').fetchone()==(1,)


def test_remembered_workspace_survives_moved_exe_and_missing_store_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(Path,"home",classmethod(lambda cls:tmp_path/"home"))
    folder=tmp_path/"fixed";folder.mkdir();(folder/"autominer.db").write_bytes(b"placeholder")
    storage.remember(folder)
    monkeypatch.setattr(sys,"frozen",True,raising=False)
    monkeypatch.setattr(sys,"executable",str(tmp_path/"moved"/"AutoMiner.exe"))
    assert storage.data_directory()==folder
    (folder/"autominer.db").unlink()
    with pytest.raises(RuntimeError):storage.data_directory()
