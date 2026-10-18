"""One user execution in history; physical jobs remain immutable execution steps."""
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .service import all_of, audit, create, get, locked
from .store import Record, now


def authenticated(x_api_key: str = Header(default='')):
    from .main import auth
    return auth(x_api_key)


router = APIRouter(prefix='/api/scan-runs', dependencies=[Depends(authenticated)])


class RunInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_id: str
    name: str = Field(min_length=1, max_length=100)
    job_ids: list[str] = Field(min_length=1, max_length=500)
    discovery_ids: list[str] = Field(default_factory=list, max_length=50)


def members(s, root):
    identifiers = list(dict.fromkeys(root.get('job_ids', []) + ([root['job_id']] if root.get('job_id') else [])))
    if root.get('is_auto_run'):
        identifiers = list(dict.fromkeys(identifiers + [j['id'] for j in all_of(s, 'job') if j.get('auto_scan_id') == root['id']]))
    jobs = [get(s, ident, 'job') for ident in identifiers]
    discoveries = [get(s, ident, 'discovery') for ident in root.get('discovery_ids', [])]
    if any(r['target_id'] != root['target_id'] for r in jobs + discoveries):
        raise HTTPException(400, '检查批次包含其他目标的记录')
    return jobs, discoveries


def aggregate(s, root):
    jobs, discoveries = members(s, root)
    if root.get('is_auto_run'):
        status = root['status']
    else:
        states = {j['status'] for j in jobs + discoveries}
        status = ('running' if states.intersection(('running','queued')) else
                  'blocked' if 'blocked' in states else 'paused' if 'paused' in states else
                  'stopped' if 'stopped' in states else 'completed')
    modes = {}
    reasons = {}
    for job in jobs:
        for ident in job.get('endpoint_ids', []):
            modes.setdefault(ident, set()).add(job.get('endpoint_test_types', {}).get(ident, 'both'))
            if job.get('test_rationale', {}).get(ident):
                reasons.setdefault(ident, []).append(job['test_rationale'][ident])
    return dict(root, is_run=True, status=status, child_job_ids=[j['id'] for j in jobs],
        job_count=len(jobs), endpoint_ids=list(modes),
        endpoint_test_types={ident: next(iter(values)) if len(values) == 1 else 'multiple' for ident, values in modes.items()},
        endpoint_test_modes={ident: sorted(values) for ident, values in modes.items()},
        test_rationale={ident: '\n'.join(dict.fromkeys(values)) for ident, values in reasons.items()},
        used=sum(j.get('used', 0) for j in jobs + discoveries),
        request_budget=root.get('request_budget', sum(j.get('request_budget', 0) for j in jobs + discoveries)),
        discovery_used=sum(d.get('used', 0) for d in discoveries))


def scope(s, ident, target_id=None):
    record = s.get(Record, ident)
    if not record or record.kind not in ('job', 'scan_run', 'auto_scan'):
        raise HTTPException(404, '任务不存在')
    root = get(s, ident)
    if target_id and root['target_id'] != target_id:
        raise HTTPException(400, '任务不属于当前目标')
    if record.kind == 'job':
        return root, [ident], []
    if record.kind == 'auto_scan':
        root = dict(root, is_auto_run=True, name='自动检查', discovery_ids=[root['discovery_id']])
    result = aggregate(s, root)
    return result, result['child_job_ids'], result.get('discovery_ids', [])


def history(s):
    roots = all_of(s, 'scan_run') + [dict(row, is_auto_run=True, name='自动检查', discovery_ids=[row['discovery_id']]) for row in all_of(s, 'auto_scan')]
    groups = [aggregate(s, root) for root in roots]
    hidden = {ident for group in groups for ident in group['child_job_ids']}
    return groups + [j for j in all_of(s, 'job') if j['id'] not in hidden]


@router.post('')
def create_run(body: RunInput):
    if len(set(body.job_ids)) != len(body.job_ids) or len(set(body.discovery_ids)) != len(body.discovery_ids):
        raise HTTPException(400, '检测步骤或接口发现记录不能重复')
    with locked() as s:
        get(s, body.target_id, 'target')
        candidate = dict(body.model_dump())
        jobs, discoveries = members(s, candidate)
        if any(j.get('auto_scan_id') for j in jobs):
            raise HTTPException(400, '自动检查已有总任务，不能重复整合')
        if any(j['status'] in ('queued','running','paused') for j in jobs + discoveries):
            raise HTTPException(409, '进行中的任务不能作为历史检查整合')
        for existing in all_of(s, 'scan_run'):
            if set(existing['job_ids']) == set(body.job_ids) and set(existing.get('discovery_ids', [])) == set(body.discovery_ids):
                return aggregate(s, existing)
            if set(existing['job_ids']).intersection(body.job_ids) or set(existing.get('discovery_ids', [])).intersection(body.discovery_ids):
                raise HTTPException(409, '部分记录已属于其他检查，不能重复整合')
        root = create(s, 'scan_run', dict(candidate, status=aggregate(s, candidate)['status'], created_at=min(j.get('created_at', now()) for j in jobs),
                                         grouped_at=now()))
        audit(s, 'scan_run_grouped', root['id'], '单次用户检查整合；原检测步骤、证据和授权均未修改')
        return aggregate(s, root)
