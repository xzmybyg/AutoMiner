"""Persistent model connections and explicit operator provider trust."""

import os
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .schemas import ModelInput
from .security import encrypt
from .service import all_of, audit, create, get, locked, save
from .store import Session


def authenticated(x_api_key: str = Header(default="")):
    from .main import auth

    return auth(x_api_key)


router = APIRouter(prefix="/api", dependencies=[Depends(authenticated)])
SETTING_KEYS = (
    "MODEL_CLOUD_BASE_URLS",
    "MODEL_LOCAL_BASE_URLS",
    "MODEL_MAX_USD_PER_MILLION_TOKENS",
)


def validated_url(value, local):
    value = value.strip().rstrip("/")
    try:
        url = urlsplit(value)
        if (
            url.scheme not in ("http", "https")
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or (not local and url.scheme != "https")
            or any(c.isspace() or ord(c) < 32 for c in value)
        ):
            raise ValueError()
        _ = url.port
    except ValueError:
        raise HTTPException(
            400, "模型地址无效；云模型要求 HTTPS，禁止凭证、空白和查询参数"
        )
    return value


def public_model(row):
    return {
        **{k: v for k, v in row.items() if k not in ("encrypted_key", "api_key")},
        "has_api_key": bool(row.get("has_api_key", row.get("encrypted_key"))),
    }


def provider_settings():
    settings = {
        key: os.getenv(key, "0" if key == SETTING_KEYS[2] else "")
        for key in SETTING_KEYS
    }
    with Session() as s:
        rows = all_of(s, "model_settings")
    if rows:
        settings.update({key: rows[0][key] for key in SETTING_KEYS})
    return settings


class ProviderSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    MODEL_CLOUD_BASE_URLS: str = Field(default="", max_length=12000)
    MODEL_LOCAL_BASE_URLS: str = Field(default="", max_length=12000)
    MODEL_MAX_USD_PER_MILLION_TOKENS: float = Field(
        default=0, ge=0, le=100000, allow_inf_nan=False
    )

    @field_validator("MODEL_CLOUD_BASE_URLS", "MODEL_LOCAL_BASE_URLS")
    @classmethod
    def urls(cls, value, info):
        local = info.field_name == "MODEL_LOCAL_BASE_URLS"
        return ",".join(
            dict.fromkeys(
                validated_url(u, local) for u in value.split(",") if u.strip()
            )
        )


@router.get("/model-settings")
def read_settings():
    return provider_settings()


@router.put("/model-settings")
def update_settings(body: ProviderSettings):
    with locked() as s:
        rows = all_of(s, "model_settings")
        if rows:
            row = dict(rows[0], **body.model_dump())
            save(s, row)
        else:
            row = create(s, "model_settings", body.model_dump())
        audit(s, "model_settings_updated", row["id"])
    return body.model_dump()


@router.get("/model-configs")
def list_models():
    with Session() as s:
        return [public_model(row) for row in all_of(s, "model")]


def write_model(body, ident=None):
    base_url = validated_url(body.base_url, body.local)
    if not body.name.strip() or not body.model.strip():
        raise HTTPException(400, "名称和模型 ID 不能为空")
    with locked() as s:
        old = get(s, ident, "model") if ident else None
        data = dict(body.model_dump(exclude={"api_key"}), base_url=base_url)
        if body.api_key or not old:
            data.update(
                encrypted_key=encrypt(body.api_key), has_api_key=bool(body.api_key)
            )
        else:
            data.update(
                encrypted_key=old["encrypted_key"],
                has_api_key=public_model(old)["has_api_key"],
            )
        if old:
            row = dict(old, **data)
            save(s, row)
        else:
            row = create(s, "model", data)
        audit(s, "model_updated" if old else "model_created", row["id"])
        return public_model(row)


@router.post("/model-configs")
def add_model(body: ModelInput):
    return write_model(body)


@router.put("/model-configs/{ident}")
def edit_model(ident: str, body: ModelInput):
    return write_model(body, ident)


@router.delete("/model-configs/{ident}")
def delete_model(ident: str):
    from .store import Record

    with locked() as s:
        get(s, ident, "model")
        s.delete(s.get(Record, ident))
        audit(s, "model_deleted", ident)
    return {"ok": True}
