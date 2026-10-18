import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.scan_runs import RunInput, create_run
from app.service import all_of, create, get, locked
from app.store import Session, now
from test_reporting_and_checks import seed_job

HEADERS={'X-API-Key':'test-token'}


def sample():
    target, endpoint, first=seed_job()
    with locked() as s:
        from app.service import save
        first.update(status='completed',used=1);save(s,first)
        second=create(s,'job',dict(first,id=None,endpoint_test_types={endpoint['id']:'injection_errors'}))
        unrelated=create(s,'job',dict(first,id=None))
        discovery=create(s,'discovery',dict(target_id=target['id'],used=2,request_budget=5,status='completed',created_at=now()))
        evidence=[]
        for j in (first,second,unrelated):
            e=create(s,'evidence',dict(target_id=target['id'],job_id=j['id'],endpoint_id=endpoint['id'],
                role='anonymous',url=endpoint['url'],state='complete',status=200,sent_at=now(),at=now(),checks=[]))
            evidence.append(e)
            create(s,'audit',dict(subject=j['id'],job_id=j['id'],action='job_completed',detail=j['id'],at=now()))
            create(s,'finding',dict(target_id=target['id'],job_id=j['id'],status='pending',title=j['id'],evidence_ids=[e['id']]))
    return target,endpoint,first,second,unrelated,discovery,evidence


def test_one_run_lists_once_and_scopes_all_evidence_logs_and_exports(monkeypatch):
    target,_,first,second,unrelated,discovery,evidence=sample()
    monkeypatch.setattr('app.service.request',lambda *a,**k:pytest.fail('Grouping must not send requests'))
    run=create_run(RunInput(target_id=target['id'],name='一次博客检查',job_ids=[first['id'],second['id']],discovery_ids=[discovery['id']]))
    client=TestClient(app)
    listing=client.get('/api/jobs',headers=HEADERS).json()
    assert {j['id'] for j in listing}=={run['id'],unrelated['id']}
    detail=client.get('/api/jobs/'+run['id'],headers=HEADERS).json()
    assert detail['job']['used']==4  # two test requests and two discovery requests
    assert detail['job']['request_budget']==11
    assert detail['coverage']['planned_endpoints']==1
    assert detail['coverage']['completed_requests']==2
    assert detail['endpoints'][0]['test_mode']=='multiple'
    assert {e['id'] for e in detail['evidence']}=={e['id'] for e in evidence[:2]}
    assert unrelated['id'] not in json.dumps(detail)
    summary=client.get(f"/api/targets/{target['id']}/report-summary?job_id={run['id']}",headers=HEADERS).json()
    assert summary['counts']['jobs']==1
    assert summary['counts']['complete_responses']==2
    for audience in ('technical','easy'):
        r=client.get(f"/api/targets/{target['id']}/report?job_id={run['id']}&audience={audience}&format=zip",headers=HEADERS)
        assert r.status_code==200
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            assert {e['id'] for e in json.loads(z.read('evidence.json'))}=={e['id'] for e in evidence[:2]}
    assert client.get('/api/jobs/'+first['id'],headers=HEADERS).status_code==200


def test_grouping_is_idempotent_and_does_not_rewrite_execution_records():
    target,_,first,second,_,_,_=sample()
    with Session() as s:before=[get(s,j['id'],'job') for j in (first,second)]
    body=RunInput(target_id=target['id'],name='group',job_ids=[first['id'],second['id']])
    one=create_run(body);two=create_run(body)
    assert one['id']==two['id']
    with Session() as s:
        assert len(all_of(s,'scan_run'))==1
        assert before==[get(s,j['id'],'job') for j in (first,second)]


def test_invalid_group_members_do_not_expand_scope():
    target,_,first,second,_,_,_=sample()
    with locked() as s:other=create(s,'target',dict(target,id=None))
    client=TestClient(app)
    base=dict(name='group',target_id=target['id'],job_ids=[first['id']])
    assert client.post('/api/scan-runs',json=base).status_code==401
    assert client.post('/api/scan-runs',json=dict(base,job_ids=[first['id'],first['id']]),headers=HEADERS).status_code==400
    assert client.post('/api/scan-runs',json=dict(base,target_id=other['id']),headers=HEADERS).status_code==400
    run=create_run(RunInput(**base))
    assert client.post('/api/scan-runs',json=dict(base,job_ids=[first['id'],second['id']]),headers=HEADERS).status_code==409
    assert client.get(f"/api/targets/{other['id']}/report-summary?job_id={run['id']}",headers=HEADERS).status_code==400


def test_automatic_rounds_list_as_one_run_and_stop_all_its_steps():
    target,_,first,second,unrelated,discovery,_=sample()
    from app.service import save
    with locked() as s:
        flow=create(s,'auto_scan',dict(target_id=target['id'],status='running',phase='testing',
            discovery_id=discovery['id'],job_ids=[first['id'],second['id']],request_budget=20,created_at=now()))
        for j in (first,second):
            j.update(auto_scan_id=flow['id'],status='running');save(s,j)
    client=TestClient(app)
    listed=client.get('/api/jobs',headers=HEADERS).json()
    assert {j['id'] for j in listed}=={flow['id'],unrelated['id']}
    assert client.get('/api/jobs/'+flow['id'],headers=HEADERS).json()['job']['job_count']==2
    assert client.post('/api/jobs/'+flow['id']+'/stop',json={},headers=HEADERS).status_code==200
    with Session() as s:
        assert get(s,flow['id'])['status']=='stopped'
        assert all(get(s,j['id'])['status']=='stopped' for j in (first,second))
        assert get(s,unrelated['id'])['status']=='completed'


def test_active_history_cannot_be_regrouped():
    target,_,first,_,_,_,_=sample()
    from app.service import save
    with locked() as s:first['status']='running';save(s,first)
    response=TestClient(app).post('/api/scan-runs',headers=HEADERS,json=dict(target_id=target['id'],name='no',job_ids=[first['id']]))
    assert response.status_code==409
