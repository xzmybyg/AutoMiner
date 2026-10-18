import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.service import get,locked,save,process_job
from app.store import Session,now
from test_discovery import fixture


def setup():
    target=fixture();client=TestClient(app);client.headers.update({"X-API-Key":"test-token"})
    account=client.post(f"/api/targets/{target['id']}/accounts",json=dict(name="admin",role="admin",headers={"Authorization":"test-secret"},synthetic_data_only=True)).json()
    return target,client,account["id"]


@pytest.mark.parametrize("anonymous,status,body,truncated,expected",[
    (401,200,'{"id":1,"role":"admin"}',False,"valid"),
    (401,200,'<html>app shell</html>',False,"inconclusive"),
    (200,200,'{"id":1,"role":"admin"}',False,"inconclusive"),
    (401,401,'{}',False,"invalid"),
    (401,200,'{"id":1,"role":"user"}',False,"inconclusive"),
    (401,200,'{"role":"admin"}',False,"inconclusive"),
    (401,200,'{"id":{},"role":"admin"}',False,"inconclusive"),
    (401,200,'{"id":1,"role":"admin"}',True,"inconclusive"),
])
def test_verification_requires_identity_evidence(monkeypatch,anonymous,status,body,truncated,expected):
    target,client,ident=setup()
    result=client.post(f"/api/accounts/{ident}/verify",json=dict(url="https://app.example/api/me",expected_role="admin"));assert result.status_code==200
    job_id=result.json()["job_id"]
    with locked() as s:
        job=get(s,job_id);job.update(status="running",deadline=now()+60);save(s,job)
    calls=[]
    def request(target,url,headers,before_send):
        before_send();calls.append(url)
        authenticated=bool(headers)
        return dict(status=status if authenticated else anonymous,headers={"Content-Type":"application/json"},body=body if authenticated else '{}',truncated=truncated)
    monkeypatch.setattr("app.service.request",request)
    process_job(job_id)
    with Session() as s:
        row=get(s,ident)
        assert row["last_validation"]["status"]==expected
        assert len(row["last_validation"]["evidence_ids"])==2
        assert get(s,target["id"])["used"]==2
    assert len(calls)==2


def test_scope_rejected_and_update_invalidates_pending_check():
    target,client,ident=setup()
    bad=client.post(f"/api/accounts/{ident}/verify",json={"url":"https://other.example/me"});assert bad.status_code==403
    result=client.post(f"/api/accounts/{ident}/verify",json={"url":"https://app.example/api/me"});job_id=result.json()["job_id"]
    response=client.put(f"/api/accounts/{ident}",json=dict(name="renamed",role="admin",headers={"Cookie":"session=new-test-secret"},synthetic_data_only=True));assert response.status_code==200
    with Session() as s:
        assert get(s,job_id)["status"]=="stopped"
        assert "last_validation" not in get(s,ident)
    assert "new-test-secret" not in client.get('/api/state').text


def test_previously_valid_session_rejected_stops_remaining_requests(monkeypatch):
    target,client,ident=setup()
    with locked() as s:
        account=get(s,ident);account["last_validation"]={"status":"valid","version":1};save(s,account)
    imported=client.post(f"/api/targets/{target['id']}/imports",json={"format":"manual","document":{"requests":[{"url":"https://app.example/one"},{"url":"https://app.example/two"}]}}).json()["imported"]
    response=client.post('/api/jobs',json=dict(target_id=target['id'],endpoint_ids=[e['id'] for e in imported],account_ids=[ident],endpoint_test_types={e['id']:"role_compare" for e in imported},request_budget=4,duration_seconds=60));job_id=response.json()['id']
    with locked() as s:
        job=get(s,job_id);job.update(status="running",deadline=now()+60);save(s,job)
    calls=[]
    def request(target,url,headers,before_send):
        before_send();calls.append(url);return dict(status=401,headers={"Content-Type":"application/json"},body='{}',truncated=False)
    monkeypatch.setattr('app.service.request',request)
    process_job(job_id)
    with Session() as s:
        assert get(s,ident)['last_validation']['status']=='invalid'
        assert get(s,job_id)['status']=='blocked'
    assert len(calls)==2
