import importlib.util
import json
from pathlib import Path
import sqlite3
from contextlib import closing

import pytest

spec=importlib.util.spec_from_file_location('consolidate_data',Path(__file__).resolve().parents[2]/'scripts/consolidate_data.py')
merge=importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)


@pytest.fixture(autouse=True)
def no_desktop_processes(monkeypatch):
    monkeypatch.setattr(merge, 'desktop_processes', lambda: [])


def write(directory, rows):
    directory.mkdir(parents=True,exist_ok=True)
    with closing(sqlite3.connect(directory/'autominer.db')) as c:
        c.execute('create table records(id text primary key,kind text,payload text)')
        c.executemany('insert into records values(?,?,?)',[(r['id'],kind,json.dumps(r)) for kind,r in rows])
        c.commit()


def test_union_preserves_ids_and_conflicting_primary_records(tmp_path):
    primary,source=tmp_path/'primary',tmp_path/'source'
    write(primary,[('target',{'id':'same','name':'primary'})])
    write(source,[('target',{'id':'same','name':'secondary'}),('target',{'id':'other'})])
    result=merge.consolidate(primary,source)
    records={ident:data for ident,_,data in merge.read_database(primary/'autominer.db')}
    assert records['same']['name']=='primary' and 'other' in records
    assert result['conflicts']==1
    assert json.loads((Path(result['backup'])/'conflicts.json').read_text())[0]['incoming']['name']=='secondary'


def test_damaged_primary_is_archived_without_promoting_fragments(tmp_path):
    primary,source=tmp_path/'primary',tmp_path/'source'
    primary.mkdir();damaged=b'not a SQLite database'
    (primary/'autominer.db').write_bytes(damaged)
    (primary/'credential-key.dpapi').write_bytes(b'existing-protected-key')
    (primary/'settings.json').write_text('{"setting":"kept"}')
    write(source,[('target',{'id':'healthy'})])
    recovered=tmp_path/'fragments.json';recovered.write_text('[{"id":"untrusted"}]')
    result=merge.consolidate(primary,source,recovered)
    assert result['primary_damaged']
    assert (Path(result['backup'])/'primary/autominer.db').read_bytes()==damaged
    assert (primary/'credential-key.dpapi').read_bytes()==b'existing-protected-key'
    assert json.loads((primary/'settings.json').read_text())=={'setting':'kept'}
    assert 'untrusted' not in {ident for ident,_,_ in merge.read_database(primary/'autominer.db')}


def test_missing_evidence_refuses_install_and_keeps_primary(tmp_path):
    primary,source=tmp_path/'primary',tmp_path/'source'
    write(primary,[('target',{'id':'keep'})])
    write(source,[('target',{'id':'target'}),('finding',{'id':'finding','target_id':'target','evidence_ids':['missing']})])
    before=(primary/'autominer.db').read_bytes()
    with pytest.raises(ValueError,match='证据关联'):
        merge.consolidate(primary,source)
    assert (primary/'autominer.db').read_bytes()==before


def test_live_workspace_is_not_replaced(tmp_path):
    primary,source=tmp_path/'primary',tmp_path/'source'
    write(primary,[('target',{'id':'keep'})]);write(source,[('target',{'id':'other'})])
    with merge.workspace_lock(source):
        with pytest.raises(RuntimeError,match='关闭'):
            merge.consolidate(primary,source)


def test_running_desktop_blocks_merge_even_when_file_lock_is_available(tmp_path, monkeypatch):
    primary,source=tmp_path/'primary',tmp_path/'source'
    write(primary,[('target',{'id':'keep'})]);write(source,[('target',{'id':'other'})])
    before=(primary/'autominer.db').read_bytes()
    monkeypatch.setattr(merge, 'desktop_processes', lambda: ['123'])
    with pytest.raises(RuntimeError,match='后台进程'):
        merge.consolidate(primary,source)
    assert (primary/'autominer.db').read_bytes()==before
    assert not (primary/'backups').exists()


def test_unfinished_jobs_stopped_and_repeated_merge_deduplicates(tmp_path):
    primary,source=tmp_path/'primary',tmp_path/'source'
    primary.mkdir()
    write(source,[('target',{'id':'target'}),('endpoint',{'id':'endpoint','target_id':'target'}),
        ('job',{'id':'job','target_id':'target','endpoint_ids':['endpoint'],'status':'running'}),
        ('evidence',{'id':'evidence','target_id':'target','job_id':'job','state':'in_flight'})])
    assert merge.consolidate(primary,source)['stopped_jobs']==1
    merge.consolidate(primary,source)
    records={ident:r for ident,_,r in merge.read_database(primary/'autominer.db')}
    assert records['job']['status']=='stopped'
    assert records['evidence']['state']=='interrupted'
    assert sum(k=='job' for _,k,_ in merge.read_database(primary/'autominer.db'))==1


def test_credentials_are_reencrypted_for_primary_key(tmp_path):
    from cryptography.fernet import Fernet
    from desktop.windows import protect
    primary,source=tmp_path/'primary',tmp_path/'source'
    primary.mkdir()
    first,second=Fernet.generate_key(),Fernet.generate_key()
    write(source,[('target',{'id':'target'}),('model',{'id':'model','encrypted_key':Fernet(first).encrypt(b'"test-only-secret"').decode()})])
    (primary/'credential-key.dpapi').write_bytes(protect(second))
    (source/'credential-key.dpapi').write_bytes(protect(first))
    merge.consolidate(primary,source)
    value=next(r for _,k,r in merge.read_database(primary/'autominer.db') if k=='model')
    assert Fernet(second).decrypt(value['encrypted_key'].encode())==b'"test-only-secret"'
