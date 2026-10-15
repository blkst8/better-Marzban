"""
Shared pytest fixtures.

The panel boots a scheduler and shells out to the xray binary at import time,
so the environment is pinned before `app` is imported and the schema is created
straight from the metadata rather than through alembic.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("DOCS", "false")
os.environ.setdefault("XRAY_EXECUTABLE_PATH", str(ROOT / "tests" / "stubs" / "xray"))
os.environ.setdefault("XRAY_ASSETS_PATH", str(ROOT / "tests" / "stubs"))
os.environ["SQLALCHEMY_DATABASE_URL"] = "sqlite:///" + str(
    Path(tempfile.gettempdir()) / "marzban_test.sqlite3"
)
os.environ.setdefault("TELEGRAM_API_TOKEN", "123456:Stub-Not-Real")
os.environ.setdefault("SUDO_USERNAME", "sudo")
os.environ.setdefault("SUDO_PASSWORD", "sudo")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app import app as fastapi_app  # noqa: E402
from app.db import SessionLocal, engine  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models.admin import Admin  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _clean_database():
    """Gives every test an empty database.

    Several metrics are global aggregates, so leftover rows from an earlier
    test would make their assertions meaningless.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def admin() -> Admin:
    return Admin(username="tester", is_sudo=True)


@pytest.fixture
def client(admin) -> TestClient:
    """A TestClient with admin auth forced open.

    Overriding `Admin.get_current` keeps the route's real dependency graph while
    removing the need to mint a real JWT for every request.
    """
    fastapi_app.dependency_overrides[Admin.get_current] = lambda: admin
    fastapi_app.dependency_overrides[Admin.check_sudo_admin] = lambda: admin
    # Deliberately not used as a context manager: entering it fires the app
    # lifespan, which starts APScheduler and tries to launch a real xray core.
    # Neither belongs in a unit test.
    try:
        yield TestClient(fastapi_app)
    finally:
        fastapi_app.dependency_overrides.clear()


@pytest.fixture
def anonymous_client() -> TestClient:
    fastapi_app.dependency_overrides.clear()
    yield TestClient(fastapi_app)