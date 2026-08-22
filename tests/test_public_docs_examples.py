from pathlib import Path
import ast


EXAMPLES = (
    Path("examples/postgres_psycopg.py"),
    Path("examples/postgres_asyncpg.py"),
    Path("examples/mysql_connector.py"),
)


def test_public_examples_exist():
    for path in EXAMPLES:
        assert path.is_file(), f"missing public example: {path}"


def test_public_examples_parse_as_python():
    for path in EXAMPLES:
        source = path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(path))


def test_public_examples_do_not_hardcode_known_passwords():
    forbidden = (
        'password="postgres"',
        'password="root"',
        'password="password"',
    )

    for path in EXAMPLES:
        source = path.read_text(encoding="utf-8")
        for value in forbidden:
            assert value not in source, f"{path} contains hardcoded credentials"


def test_examples_readme_mentions_all_public_examples():
    readme = Path("examples/README.md").read_text(encoding="utf-8")

    for path in EXAMPLES:
        assert path.name in readme


def test_security_and_architecture_docs_exist():
    required = (
        Path("SECURITY.md"),
        Path("docs/ARCHITECTURE.md"),
        Path("docs/THREAT_MODEL.md"),
    )

    for path in required:
        assert path.is_file(), f"missing documentation: {path}"
