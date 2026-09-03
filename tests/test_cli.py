from pathlib import Path

import pytest
from typer.testing import CliRunner

from hacker_ai.cli import app


def test_scope_check_rejects_out_of_scope_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    assert runner.invoke(app, ["init", "."]).exit_code == 0
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        """program:
  name: CLI test
scope:
  included:
    - type: domain
      value: example.com
""",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["program", "import", str(scope_file)]).exit_code == 0

    result = runner.invoke(app, ["scope", "check", "https://outside.test"])

    assert result.exit_code == 2
    assert "DENIED" in result.stdout
    assert "not in the allowlist" in result.stdout
