import os
import shutil
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/bench.sh"


def make_repo(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(SCRIPT, scripts / "bench.sh")
    (repo / "tracked").write_text("clean\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=repo,
        check=True,
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cargo_args = tmp_path / "cargo-args"
    write_executable(bin_dir / "uname", "#!/bin/sh\necho Darwin\n")
    write_executable(
        bin_dir / "cargo",
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$CARGO_ARGS"\n',
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{environment['PATH']}",
            "BENCH": "speedup",
            "CARGO_ARGS": str(cargo_args),
        }
    )
    return repo, cargo_args, environment


def run_bench(
    repo: Path, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "scripts/bench.sh"],
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_default_save_uses_clean_commit_stamp(tmp_path: Path) -> None:
    repo, cargo_args, environment = make_repo(tmp_path)
    stamp = subprocess.run(
        ["git", "rev-parse", "--short=12", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    result = run_bench(repo, environment)

    assert result.returncode == 0, result.stderr
    assert cargo_args.read_text().splitlines()[-2:] == ["--save-baseline", stamp]


def test_default_save_rejects_dirty_source(tmp_path: Path) -> None:
    repo, cargo_args, environment = make_repo(tmp_path)
    (repo / "tracked").write_text("dirty\n")

    result = run_bench(repo, environment)

    assert result.returncode != 0
    assert "commit changes before benchmarking" in result.stderr
    assert not cargo_args.exists()


def test_explicit_save_remains_available_for_dirty_experiments(tmp_path: Path) -> None:
    repo, cargo_args, environment = make_repo(tmp_path)
    (repo / "tracked").write_text("dirty\n")
    environment["SAVE"] = "experiment"

    result = run_bench(repo, environment)

    assert result.returncode == 0, result.stderr
    assert cargo_args.read_text().splitlines()[-2:] == ["--save-baseline", "experiment"]


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(0o755)
