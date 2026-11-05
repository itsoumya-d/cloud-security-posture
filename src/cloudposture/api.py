from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker

from .auth import load_api_keys, require_role
from .db import SessionLocal, init_db
from .service import CloudPostureService, NotFoundError, ValidationError


class AccountIn(BaseModel):
    provider: str
    account_id: str
    name: str


class SyncIn(BaseModel):
    resources: list[dict[str, Any]] = Field(default_factory=list)


class ResolveIn(BaseModel):
    note: str


def create_app(session_factory: sessionmaker = SessionLocal, api_keys: dict[str, str] | None = None, init_database: bool = True) -> FastAPI:
    if init_database:
        init_db()
    keys = api_keys or load_api_keys()
    app = FastAPI(title="Cloud security posture", version="1.0.0")

    def db_session():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    viewer = require_role("viewer", keys)
    analyst = require_role("analyst", keys)
    admin = require_role("admin", keys)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready(session: Session = Depends(db_session)) -> dict[str, str]:
        session.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "ready"}

    @app.post("/accounts")
    def create_account(payload: AccountIn, session: Session = Depends(db_session), actor: str = Depends(admin)) -> dict[str, Any]:
        try:
            row = CloudPostureService(session, actor).create_account(payload.provider, payload.account_id, payload.name)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": row.id, "provider": row.provider, "account_id": row.account_id}

    @app.post("/accounts/{account_id}/sync")
    def sync(account_id: int, payload: SyncIn, session: Session = Depends(db_session), actor: str = Depends(analyst)) -> dict[str, Any]:
        try:
            return CloudPostureService(session, actor).sync_resources(account_id, payload.resources)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/findings")
    def findings(status: str | None = None, session: Session = Depends(db_session), _: str = Depends(viewer)) -> dict[str, Any]:
        return {"findings": [{
            "id": row.id, "resource_id": row.resource_id, "rule_id": row.rule_id,
            "title": row.title, "severity": row.severity, "status": row.status,
        } for row in CloudPostureService(session).findings(status)]}

    @app.post("/findings/{finding_id}/resolve")
    def resolve(finding_id: int, payload: ResolveIn, session: Session = Depends(db_session), actor: str = Depends(analyst)) -> dict[str, Any]:
        try:
            row = CloudPostureService(session, actor).resolve_finding(finding_id, payload.note)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": row.id, "status": row.status}

    @app.get("/summary")
    def summary(session: Session = Depends(db_session), _: str = Depends(viewer)) -> dict[str, Any]:
        return CloudPostureService(session).summary()

    @app.get("/audit")
    def audit(session: Session = Depends(db_session), _: str = Depends(admin)) -> dict[str, Any]:
        return {"audit": CloudPostureService(session).audit()}

    return app


app = create_app()
