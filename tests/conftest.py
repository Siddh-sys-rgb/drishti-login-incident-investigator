import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app

@pytest.fixture
def application(tmp_path):
    return create_app(tmp_path, testing=True)

@pytest.fixture
def client(application):
    return application.test_client()

@pytest.fixture
def csrf(client):
    return {'X-CSRF-Token': client.get('/api/bootstrap').json['csrf']}
