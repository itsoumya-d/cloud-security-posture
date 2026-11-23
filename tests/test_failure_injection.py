"""Failure injection and error path resilience tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudposture.db import Base
from cloudposture.detection_engine import (
    DetectionEngine,
    build_aws_console_login_without_mfa_rule,
)
from cloudposture.service import CloudPostureService


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    yield s
    s.close()


def test_failure_injection_malformed_telemetry_degrades_gracefully():
    engine = DetectionEngine()
    engine.register_rule(build_aws_console_login_without_mfa_rule())

    # Corrupted / malformed payload (None values, missing keys, invalid types)
    malformed_events = [
        {},
        {"eventSource": None, "eventName": 123},
        {"responseElements": "not-a-dict"},
        {"userIdentity": None},
    ]

    for evt in malformed_events:
        # Engine must not crash or throw unhandled exceptions
        alerts = engine.evaluate_event(evt)
        assert alerts == []


def test_failure_injection_db_unreachable_raises_predictable_error(session):
    service = CloudPostureService(session)
    session.close()

    with pytest.raises(Exception):
        service.get_account("non-existent-id")
