import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

temporary = TemporaryDirectory()
os.environ["DATABASE_URL"] = "sqlite:///" + str(
    Path(temporary.name) / "test.db"
).replace("\\", "/")
os.environ["APP_TOKEN"] = "test-token"
os.environ["INTERNAL_TOKEN"] = "internal-token"
os.environ["MODEL_CLOUD_BASE_URLS"] = "https://models.example/v1"
os.environ["ENCRYPTION_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from app.store import Base, engine, init_db


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(engine)
    init_db()


@pytest.fixture(scope="session", autouse=True)
def close_engine():
    yield
    engine.dispose()
    temporary.cleanup()
