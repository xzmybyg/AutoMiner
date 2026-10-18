import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.readable_report import export, summary
from app.service import create, locked
from app.store import Session
from test_reporting_and_checks import seed_job


def seed_response(job, target, endpoint, **extra):
    with locked() as s:
        return create(s, 'evidence', dict(target_id=target['id'], job_id=job['id'],
            endpoint_id=endpoint['id'], state='complete', status=200, sent_at=1,
            checks=[{'id':'csp-policy','status':'hit'}],
            http_exchange={'response':{'body':'PRIVATE-RESPONSE-NOT-FOR-SUMMARY','truncated':True}}, **extra))


def test_summary_has_no_raw_responses_and_preserves_pending_state():
    target, endpoint, job = seed_job()
    ev = seed_response(job, target, endpoint)
    with locked() as s:
        create(s,'finding',dict(target_id=target['id'],title='CSP observation',status='pending',evidence_ids=[ev['id']]))
    with Session() as s:
        result=summary(s,target['id'],job['id'])
    assert result['counts']['confirmed_findings']==0
    assert result['counts']['pending_findings']==1
    assert result['counts']['truncated_responses']==1
    assert result['counts']['requested_endpoints']==1
    assert result['advice'][0]['id']=='csp-policy'
    assert 'PRIVATE-RESPONSE' not in json.dumps(result)
    assert result['findings'][0]['status']=='pending'


def test_empty_history_does_not_claim_safe_or_checked():
    target, _, job=seed_job()
    with Session() as s:
        result=summary(s,target['id'],job['id'])
    assert result['counts']['complete_responses']==0
    assert result['counts']['requested_endpoints']==0
    assert '不等于' in result['headline']
    assert not result['advice']


def test_scope_does_not_include_other_task_and_rejects_wrong_target():
    target, endpoint, job=seed_job()
    with locked() as s:
        other=create(s,'job',dict(target_id=target['id'],status='completed',endpoint_ids=[]))
        foreign=create(s,'target',{'name':'other'})
    ev=seed_response(other,target,endpoint)
    with locked() as s:
        create(s,'finding',dict(target_id=target['id'],title='OTHER-TASK',status='pending',evidence_ids=[ev['id']]))
    client=TestClient(app)
    route=f"/api/targets/{target['id']}/report-summary?job_id={job['id']}"
    assert client.get(route).status_code==401
    result=client.get(route,headers={'X-API-Key':'test-token'})
    assert result.status_code==200
    assert result.json()['findings']==[]
    wrong=client.get(f"/api/targets/{foreign['id']}/report-summary?job_id={job['id']}",headers={'X-API-Key':'test-token'})
    assert wrong.status_code==400


@pytest.mark.parametrize('fmt',['md','html','zip'])
def test_easy_exports_keep_task_scope_and_escape_html(fmt):
    target, endpoint, job=seed_job()
    ev=seed_response(job,target,endpoint)
    with locked() as s:
        create(s,'finding',dict(target_id=target['id'],title='<script>alert(1)</script>',status='pending',evidence_ids=[ev['id']]))
    client=TestClient(app)
    response=client.get(f"/api/targets/{target['id']}/report?audience=easy&format={fmt}&job_id={job['id']}",headers={'X-API-Key':'test-token'})
    assert response.status_code==200
    if fmt=='html':
        assert '<script>' not in response.text
        assert '&lt;script&gt;' in response.text
    elif fmt=='zip':
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            saved=json.loads(z.read('evidence.json'))
            assert [e['id'] for e in saved]==[ev['id']]
            assert '易懂版'.encode() in z.read('report.md')
    else:
        assert '待确认' in response.text


def test_unbacked_verified_record_is_not_counted_as_confirmed():
    target, _, job=seed_job()
    with locked() as s:
        create(s,'finding',dict(target_id=target['id'],title='missing evidence',status='verified',evidence_ids=['missing']))
    with Session() as s:
        assert summary(s,target['id'])['counts']['confirmed_findings']==0


def test_unknown_audience_rejected_and_technical_default_unchanged():
    target, _, job=seed_job()
    client=TestClient(app);headers={'X-API-Key':'test-token'}
    route=f"/api/targets/{target['id']}/report?job_id={job['id']}"
    assert client.get(route+'&audience=unknown',headers=headers).status_code==422
    response=client.get(route,headers=headers)
    assert response.status_code==200
    assert '漏洞报告' in response.text
    assert '易懂版' not in response.text
