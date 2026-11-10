"""Shared fixtures: ZOOMRIYA ID's own test database, data folder and Redis database.

Tests run in ``<dev database>_test`` (``zoomriya_id_test``), or
TEST_DATABASE_URL, never the real accounts. Create it once:

    sudo -u postgres createdb -O zoomriya zoomriya_id_test
"""

import os
import tempfile
from urllib.parse import urlsplit, urlunsplit

from dotenv import dotenv_values

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Redis database 15, as Photos' tests use: nothing reaches the dev servers.
TEST_REDIS_DB = 15
_redis = urlsplit(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
os.environ["REDIS_URL"] = urlunsplit(_redis._replace(path=f"/{TEST_REDIS_DB}"))

_DEV_DATABASE_URL = (
    os.environ.get("DATABASE_URL")
    or dotenv_values(os.path.join(_BACKEND_DIR, ".env")).get("DATABASE_URL")
    or "postgresql+psycopg://zoomriya:root@localhost:5432/zoomriya_id"
)
if os.environ.get("TEST_DATABASE_URL"):
    TEST_DATABASE_URL = os.environ["TEST_DATABASE_URL"]
else:
    _dev = urlsplit(_DEV_DATABASE_URL)
    TEST_DATABASE_URL = urlunsplit(_dev._replace(path=f"{_dev.path.rstrip('/')}_test"))
TEST_DATABASE_NAME = urlsplit(TEST_DATABASE_URL).path.lstrip("/")
if not TEST_DATABASE_NAME.endswith("_test"):
    raise RuntimeError(
        f"Refusing to run tests against {TEST_DATABASE_NAME!r}: "
        "the test database's name must end in _test"
    )
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

# A throwaway data folder: its own signing key and profile photos.
os.environ["ZOOMRIYA_ID_DATA_DIR"] = tempfile.mkdtemp(prefix="zoomriya-id-test-")
os.environ.pop("JWT_PRIVATE_KEY_PATH", None)

import pytest  # noqa: E402
import redis  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.main import app, limiter  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    """Bring the test database to the latest migration before any test runs."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine
    from sqlalchemy.exc import OperationalError

    assert settings.DATABASE_URL == TEST_DATABASE_URL, settings.DATABASE_URL
    try:
        create_engine(settings.DATABASE_URL).connect().close()
    except OperationalError as exc:
        if "does not exist" not in str(exc):
            raise
        dev = urlsplit(_DEV_DATABASE_URL)
        pytest.exit(
            f"The test database {TEST_DATABASE_NAME} doesn't exist yet. Create it once:\n"
            f"  sudo -u postgres createdb -O {dev.username} {TEST_DATABASE_NAME}",
            returncode=4,
        )
    config = Config(os.path.join(_BACKEND_DIR, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(_BACKEND_DIR, "migrations"))
    command.upgrade(config, "head")
    yield


@pytest.fixture(scope="session", autouse=True)
def _empty_test_redis():
    assert urlsplit(settings.REDIS_URL).path == f"/{TEST_REDIS_DB}", settings.REDIS_URL
    client = redis.Redis.from_url(settings.REDIS_URL)
    try:
        client.flushdb()
    except redis.ConnectionError:
        pass  # no Redis: the tests that need it skip themselves
    yield
    client.close()


@pytest.fixture(autouse=True)
def _no_rate_limits_between_tests():
    """Every test signs in many times from the same address."""
    limiter.buckets.clear()
    yield
    limiter.buckets.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
