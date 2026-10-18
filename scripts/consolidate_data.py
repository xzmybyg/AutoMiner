"""Offline, backed-up merge into the desktop default store. Never starts workers."""
import argparse
import csv
from contextlib import ExitStack, contextmanager, closing
from datetime import datetime
import json
import io
from pathlib import Path
import shutil
import sqlite3
import sys
import subprocess
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def desktop_processes():
    result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq AutoMiner.exe', '/FO', 'CSV', '/NH'],
                            capture_output=True, text=True, check=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return [row[1] for row in csv.reader(io.StringIO(result.stdout))
            if len(row) > 1 and row[0].lower() == 'autominer.exe']


@contextmanager
def workspace_lock(directory):
    import msvcrt
    with (directory / 'app.lock').open('a+b') as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b'0'); handle.flush()
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise RuntimeError(f'请先关闭使用此数据目录的 AutoMiner：{directory}') from exc
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def read_database(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as connection:
        if connection.execute('pragma integrity_check').fetchall() != [('ok',)]:
            raise ValueError('数据库完整性检查失败')
        rows = []
        for ident, kind, payload in connection.execute('select id,kind,payload from records'):
            value = json.loads(payload)
            if value.get('id') != ident:
                raise ValueError('记录 ID 不一致')
            rows.append((ident, kind, value))
        return rows


def translate_credentials(rows, source, destination):
    secret_rows = [(value, field) for _, _, value in rows
                   for field in ('encrypted_headers', 'encrypted_key') if value.get(field)]
    if not secret_rows:
        return
    from cryptography.fernet import Fernet
    from desktop.windows import protect
    source_key = source / 'credential-key.dpapi'
    destination_key = destination / 'credential-key.dpapi'
    if not source_key.exists() or not destination_key.exists():
        raise ValueError('缺少密钥，未修改主库；不能静默丢弃账号或模型凭证')
    before = Fernet(protect(source_key.read_bytes(), decrypt=True))
    after = Fernet(protect(destination_key.read_bytes(), decrypt=True))
    for record, field in secret_rows:
        plain = before.decrypt(record[field].encode())
        record[field] = after.encrypt(plain).decode()


def validate(rows):
    records = {ident: (kind, value) for ident, kind, value in rows}
    for ident, kind, row in rows:
        if row.get('target_id') and kind not in ('audit',):
            if records.get(row['target_id'], (None,))[0] != 'target':
                raise ValueError(f'缺少目标关联：{kind} {ident}')
        if kind == 'job':
            for endpoint in row.get('endpoint_ids', []):
                linked = records.get(endpoint)
                if not linked or linked[0] != 'endpoint' or linked[1]['target_id'] != row['target_id']:
                    raise ValueError('任务接口关联不完整')
        if kind in ('finding', 'verification'):
            for evidence in row.get('evidence_ids', []):
                linked = records.get(evidence)
                if not linked or linked[0] != 'evidence' or linked[1]['target_id'] != row['target_id']:
                    raise ValueError('发现或验证记录的证据关联不完整')
        if kind == 'evidence' and row.get('job_id'):
            linked = records.get(row['job_id'])
            if not linked or linked[0] != 'job' or linked[1]['target_id'] != row['target_id']:
                raise ValueError('证据任务关联不完整')


def consolidate(destination, source, recovered=None):
    destination, source = Path(destination).resolve(), Path(source).resolve()
    if destination == source or not (source / 'autominer.db').is_file():
        raise ValueError('需要不同的主工作库与现有来源工作库')
    if desktop_processes():
        raise RuntimeError('请先关闭所有 AutoMiner 窗口与后台进程，再离线整合数据；仅检查文件锁不足以防止旧连接继续读取旧文件')
    destination.mkdir(parents=True, exist_ok=True)
    backup = destination / 'backups' / ('consolidation-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid4().hex[:6])
    with ExitStack() as stack:
        for directory in sorted((destination, source), key=str):
            stack.enter_context(workspace_lock(directory))
        backup.mkdir(parents=True)
        for label, directory in [('primary', destination), ('blog', source)]:
            archive = backup / label
            archive.mkdir()
            for name in ('autominer.db','autominer.db-wal','autominer.db-shm','autominer.db-journal','credential-key.dpapi','settings.json'):
                path = directory / name
                if path.is_file():
                    shutil.copy2(path, archive / name)
        if recovered and Path(recovered).is_file():
            shutil.copy2(recovered, backup / 'damaged-record-fragments.json')
        primary = []
        damaged = False
        if (destination / 'autominer.db').exists():
            try:
                primary = read_database(destination / 'autominer.db')
            except (sqlite3.DatabaseError, ValueError, json.JSONDecodeError):
                damaged = True
        incoming = read_database(source / 'autominer.db')
        translate_credentials(incoming, source, destination)
        combined = {ident: (kind, data) for ident, kind, data in primary}
        conflicts = []
        for ident, kind, value in incoming:
            if ident in combined:
                if combined[ident] != (kind, value):
                    if combined[ident][0] != kind:
                        raise ValueError('相同 ID 的记录类型冲突，未替换主库')
                    conflicts.append(dict(id=ident, kind=kind, incoming=value))
            else:
                combined[ident] = (kind, value)
        rows = [(ident, kind, value) for ident, (kind, value) in combined.items()]
        validate(rows)
        stopped = 0
        for _, kind, value in rows:
            if kind in ('job','discovery','auto_scan') and value.get('status') in ('queued','running','paused'):
                value.update(status='stopped', error='数据整合期间已停止，未自动重放请求')
                stopped += 1
            if kind == 'evidence' and value.get('state') in ('reserved','in_flight'):
                value.update(state='interrupted')
        audit_id = uuid4().hex
        rows.append((audit_id, 'audit', dict(id=audit_id, action='data_consolidated', subject='local',
            detail='整合完整工作库；损坏原库归档；未自动重放请求', at=datetime.now().timestamp())))
        stage = destination / ('merge-' + uuid4().hex + '.db')
        with closing(sqlite3.connect(stage)) as connection:
            connection.executescript('CREATE TABLE records(id VARCHAR(64) PRIMARY KEY,kind VARCHAR(32),payload TEXT);'
                'CREATE INDEX ix_records_kind ON records(kind);CREATE TABLE mutex(id INTEGER PRIMARY KEY,revision INTEGER);'
                'INSERT INTO mutex VALUES(1,0);')
            connection.executemany('insert into records values(?,?,?)',
                [(ident, kind, json.dumps(value,ensure_ascii=False)) for ident,kind,value in rows])
            connection.commit()
            if connection.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise RuntimeError('暂存库检查失败，未替换主库')
        read_database(stage)
        # Refuse to attach an old live WAL/journal to a replacement database.
        for suffix in ('-wal','-journal'):
            sidecar = destination / ('autominer.db' + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                raise RuntimeError('主库仍有日志文件；请关闭应用后重试，原件与备份均保留')
        report_dir = destination / 'reports' / 'blog-review'
        report_dir.mkdir(parents=True, exist_ok=True)
        for file in source.iterdir():
            if file.is_file() and file.suffix.lower() in ('.md','.html','.csv','.zip','.json','.png','.txt'):
                if file.name not in ('settings.json',):
                    shutil.copy2(file, report_dir / file.name)
        (backup / 'conflicts.json').write_text(json.dumps(conflicts,ensure_ascii=False,indent=2),encoding='utf-8')
        stage.replace(destination / 'autominer.db')
        installed = read_database(destination / 'autominer.db')
        validate(installed)
        result = dict(destination=str(destination), backup=str(backup), records=len(installed),
            primary_damaged=damaged, conflicts=len(conflicts), stopped_jobs=stopped,
            counts={kind:sum(k==kind for _,k,_ in installed) for kind in sorted({k for _,k,_ in installed})})
        (backup / 'merge-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--recovered')
    args=parser.parse_args()
    print(json.dumps(consolidate(args.destination,args.source,args.recovered),ensure_ascii=False))
