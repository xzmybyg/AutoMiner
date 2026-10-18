"""Account checks use ordinary budgeted jobs and never bypass the gateway."""
import hashlib
import json
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from .policy import check_url, Denied
from .schemas import AccountInput
from .service import active, all_of, audit, create, get, locked, save
from .store import now
from .security import encrypt


def authenticated(x_api_key: str = Header(default="")):
    from .main import auth
    return auth(x_api_key)


router=APIRouter(prefix="/api/accounts", dependencies=[Depends(authenticated)])


class IdentityConfig(BaseModel):
    model_config=ConfigDict(extra="forbid")
    url: str = Field(max_length=2048)
    identity_field: str = Field(default="id", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    role_field: str = Field(default="role", pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
    expected_role: str = Field(default="", max_length=100)


@router.put("/{ident}")
def update(ident: str, body: AccountInput):
    # Reuse validation but update the existing account identity, preserving history.
    for key,value in body.headers.items():
        if key.lower() not in ("authorization","cookie","x-test-account") or "\r" in value or "\n" in value:
            raise HTTPException(400,"不允许的账号请求头")
    if not body.headers or not any(body.headers.values()):
        raise HTTPException(400,"请填写登录凭证")
    with locked() as s:
        row=get(s,ident,"account")
        for job in all_of(s,"job"):
            if ident in job.get("account_ids",[]) and job["status"] in ("running","queued","paused"):
                job.update(status="stopped",error="账号凭证已更新，请重新验证后新建检查")
                save(s,job)
        row.update(name=body.name,role=body.role,encrypted_headers=encrypt(body.headers),header_names=list(body.headers),updated_at=now())
        row.pop("credential_recovery_required",None);row.pop("last_validation",None)
        save(s,row);audit(s,"account_updated",ident)
    return {"id":ident}


@router.post("/{ident}/verify")
def verify(ident: str, body: IdentityConfig):
    with locked() as s:
        account=get(s,ident,"account");target=get(s,account["target_id"],"target");active(target)
        check_url(target,body.url)
        from urllib.parse import urlsplit
        if urlsplit(body.url).query:raise Denied("登录状态接口不能包含查询参数")
        endpoint=next((e for e in all_of(s,"endpoint") if e["target_id"]==target["id"] and e["method"]=="GET" and e["url"]==body.url),None)
        if not endpoint:endpoint=create(s,"endpoint",dict(target_id=target["id"],method="GET",url=body.url,executable=True))
        account["identity_check"]=body.model_dump();save(s,account)
        target["identity_check"]=dict(body.model_dump(),expected_role="");save(s,target)
        revision=hashlib.sha256(account["encrypted_headers"].encode()).hexdigest()
        if target["request_budget"]-target["used"] < 2:raise Denied("目标剩余请求预算不足 2 次")
        job=create(s,"job",dict(target_id=target["id"],endpoint_ids=[endpoint["id"]],account_ids=[ident],endpoint_test_types={endpoint["id"]:"role_compare"},request_budget=2,duration_seconds=60,version=target["version"],status="queued",used=0,created_at=now(),deadline=0,name="验证账号登录状态",identity_check=dict(body.model_dump(),account_id=ident,revision=revision)))
        audit(s,"job_created",job["id"],"账号登录状态验证；2 次只读请求")
    return {"job_id":job["id"]}



def finalize(s,job):
    config=job.get("identity_check")
    if not config:return
    account=get(s,config["account_id"],"account")
    if hashlib.sha256(account["encrypted_headers"].encode()).hexdigest()!=config["revision"]:return
    target=get(s,job["target_id"],"target")
    if target["version"]!=job["version"]:return
    evidence=[e for e in all_of(s,"evidence") if e.get("job_id")==job["id"]]
    anonymous=next((e for e in evidence if not e.get("account_id")),{})
    authenticated=next((e for e in evidence if e.get("account_id")==account["id"]),{})
    status,reason="inconclusive","没有获得明确的登录身份响应，请检查接口地址和返回字段"
    if authenticated.get("state")=="complete" and authenticated.get("status") in (401,403):
        status,reason="invalid","服务端拒绝了此会话，请更新凭证后重新验证"
    elif anonymous.get("status") in (401,403) and authenticated.get("status")==200 and authenticated.get("state")=="complete":
        response=authenticated.get("http_exchange",{}).get("response",{})
        try:
            value=json.loads(response.get("body",""))
            if isinstance(value,dict):
                value=value.get("data",value)
                if isinstance(value,dict) and isinstance(value.get(config["identity_field"]),(str,int)) and not isinstance(value.get(config["identity_field"]),bool) and value.get(config["identity_field"]) not in (None,"", "[REDACTED]") and not response.get("truncated"):
                    if not config["expected_role"] or value.get(config["role_field"])==config["expected_role"]:
                        status,reason="valid",("匿名访问被拒绝，登录请求返回预期身份及角色" if config["expected_role"] else "会话有效；本次未校验角色")
                    else:reason="会话返回的角色与预期不一致，请核对账号"
        except (ValueError,TypeError):pass
    account["last_validation"]=dict(status=status,reason=reason,at=now(),job_id=job["id"],version=target["version"],evidence_ids=[e["id"] for e in evidence])
    save(s,account);audit(s,"account_validated",account["id"],status)
