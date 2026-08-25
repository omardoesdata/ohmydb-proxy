from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_non_root_runtime_user():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "USER sqlsafety" in text
    assert 'ENTRYPOINT ["ohmydb"]' in text
    assert "pip install ." in text


def test_dockerfile_does_not_embed_credentials():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8").lower()

    assert "estimator_password=" not in text
    assert "password123" not in text
    assert "root_password" not in text


def test_dockerignore_excludes_sensitive_and_build_files():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert ".env" in text
    assert ".venv" in text
    assert "dist" in text
    assert "build" in text
    assert "logs" in text


def test_compose_examples_use_environment_for_passwords():
    text = (ROOT / "docker-compose.example.yml").read_text(
        encoding="utf-8"
    )

    assert "${POSTGRES_ESTIMATOR_PASSWORD:-}" in text
    assert "${MYSQL_ESTIMATOR_PASSWORD:-}" in text
    assert "USER sqlsafety" not in text


def test_compose_contains_postgres_and_mysql_examples():
    text = (ROOT / "docker-compose.example.yml").read_text(
        encoding="utf-8"
    )

    assert "--adapter" in text
    assert "postgres" in text
    assert "mysql" in text
    assert "5433:5433" in text
    assert "3307:3307" in text
