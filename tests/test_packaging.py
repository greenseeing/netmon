import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
PYPROJECT = ROOT / "pyproject.toml"
INSTALLER = ROOT / "install.sh"

needs_uv = pytest.mark.skipif(
    shutil.which("uv") is None,
    reason="uv is not on PATH — these guard artifacts uv generates, and a pip-installed "
    "contributor must still be able to run the suite",
)


def _pinned_lines(text: str) -> list[str]:
    # Compare only what the file asserts, not how uv chose to word its header this release:
    # a future uv rephrasing its comment banner must not fail the build.
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def _export_command(text: str) -> list[str]:
    # requirements.txt documents how it is made -- uv writes its own invocation into the
    # header -- so the test executes that documentation rather than keeping a second copy of
    # the argument list here, which is exactly the drift this test exists to catch.
    for line in text.splitlines():
        stripped = line.lstrip("# ").strip()
        if stripped.startswith("uv export"):
            return stripped.split()
    pytest.fail("requirements.txt has no `uv export` command in its header comment")


class TestRequirementsTxt:
    def test_is_checked_in_and_pins_the_runtime_tree(self) -> None:
        text = REQUIREMENTS.read_text(encoding="utf-8")
        pins = _pinned_lines(text)
        assert pins, "requirements.txt is empty"
        # The dashboard is what `netmon run` shows by default, so a tui-less requirements
        # file would install a netmon whose primary command cannot start.
        names = {ln.split("==")[0].strip() for ln in pins if "==" in ln}
        assert {"scapy", "pydantic", "structlog", "cryptography", "textual"} <= names

    def test_every_pin_carries_a_hash(self) -> None:
        # The person taking the pip path is often the person who declined an unchecked
        # `curl | sh`. Hashes are what make `pip install --require-hashes` as trustworthy
        # as `uv sync` for them.
        text = REQUIREMENTS.read_text(encoding="utf-8")
        assert "--hash=sha256:" in text
        for line in _pinned_lines(text):
            if "==" in line:
                assert line.rstrip().endswith("\\"), f"pin without a hash continuation: {line}"

    def test_does_not_install_the_project_itself(self) -> None:
        # An `-e .` line would break pip's hash mode outright; the project is installed
        # separately by the installer.
        assert "-e ." not in REQUIREMENTS.read_text(encoding="utf-8")

    @needs_uv
    def test_matches_the_lockfile(self) -> None:
        text = REQUIREMENTS.read_text(encoding="utf-8")
        command = _export_command(text)
        fresh = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        assert fresh.returncode == 0, fresh.stderr
        assert _pinned_lines(fresh.stdout) == _pinned_lines(text), (
            "requirements.txt has drifted from uv.lock. Regenerate it:\n"
            f"    {' '.join(command)} > requirements.txt"
        )

    @needs_uv
    def test_lockfile_matches_pyproject(self) -> None:
        done = subprocess.run(
            ["uv", "lock", "--check"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, (
            f"uv.lock has drifted from pyproject.toml:\n{done.stderr}\nRun: uv lock"
        )


class TestInstallerFloor:
    def test_python_floor_matches_requires_python(self) -> None:
        # The installer decides whether the host's own python3 is usable. If its floor and
        # pyproject's disagree it either rejects a perfectly good interpreter, or builds a
        # venv that cannot run netmon -- and that second failure surfaces far from its cause.
        with PYPROJECT.open("rb") as f:
            requires = tomllib.load(f)["project"]["requires-python"]
        declared = requires.removeprefix(">=").strip()
        match = re.search(r"^PY_MIN=(\S+)", INSTALLER.read_text(encoding="utf-8"), re.MULTILINE)
        assert match, "install.sh has no PY_MIN"
        assert match.group(1) == declared, (
            f"install.sh PY_MIN={match.group(1)} but pyproject requires-python is {requires}"
        )


class TestDeclaredFloorIsReal:
    def test_the_interpreter_running_the_suite_satisfies_the_declared_floor(self) -> None:
        with PYPROJECT.open("rb") as f:
            requires = tomllib.load(f)["project"]["requires-python"]
        floor = tuple(int(p) for p in requires.removeprefix(">=").strip().split("."))
        assert sys.version_info[: len(floor)] >= floor


RELEASE_SH = ROOT / "scripts" / "release.sh"
NOTES_SH = ROOT / "scripts" / "changelog-notes.sh"
CHANGELOG = ROOT / "CHANGELOG.md"

# install.sh refuses to *install* a ref it does not recognise; release.sh must
# refuse to *cut* one, and netmon.py's updater must refuse to *move* to one. The
# three validators live in separate files and two separate languages (install.sh
# is curl-piped and cannot source anything), so pin them to the same answer — a
# version one accepts and another rejects either ships a tag that silently
# serves `main` to fresh installs, or moves updates to a release installs never
# get.
NOT_A_VERSION = [
    "0.3.0-rc1",  # prerelease
    "1.2",  # only two segments
    "1.2.3.4",  # four segments
    "1.2.3.",  # trailing dot
    "0..0",  # empty segment
    "..",  # empty segments
    "1.2.3;id",  # shell metacharacter
    "1.2.3 && id",  # shell metacharacter
    "$(id)",  # shell injection
    "1.2.3|sh",  # pipe
    "1" * 30 + ".2.3",  # over the 32-char cap
]
A_VERSION = ["0.1.0", "10.20.30"]


def _install_sh_verdict(candidate: str) -> bool:
    text = INSTALLER.read_text(encoding="utf-8")
    match = re.search(r"^_valid_ref\(\) \{\n.*?^\}", text, re.MULTILINE | re.DOTALL)
    assert match, "install.sh has no _valid_ref"
    # The candidate travels as an argument, never interpolated: half this list is
    # shell injection, and quoting it into the script would test the quoting.
    done = subprocess.run(
        ["bash", "-c", match.group(0) + '\n_valid_ref "$1"', "_", candidate],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode == 0


class TestVersionValidatorLockstep:
    @pytest.mark.parametrize("candidate", NOT_A_VERSION)
    def test_install_sh_and_the_updater_refuse_the_same_junk(self, candidate: str) -> None:
        import netmon

        assert not _install_sh_verdict(candidate)
        assert netmon._release_version(candidate) is None
        assert netmon._release_version("v" + candidate) is None

    @pytest.mark.parametrize("candidate", A_VERSION)
    def test_install_sh_and_the_updater_accept_the_same_releases(self, candidate: str) -> None:
        import netmon

        assert _install_sh_verdict(candidate)
        assert _install_sh_verdict("v" + candidate)
        assert netmon._release_version(candidate) is not None
        assert netmon._release_version("v" + candidate) is not None

    @pytest.mark.parametrize("version", NOT_A_VERSION)
    def test_release_sh_refuses_every_version_install_sh_would(
        self, version: str, tmp_path: Path
    ) -> None:
        # cwd is an empty tmp dir, and the version guard runs before anything
        # that touches git or the working tree, so nothing can be mutated here.
        done = subprocess.run(
            ["sh", str(RELEASE_SH), version],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode != 0, done.stdout
        assert "version must look like" in done.stderr, done.stderr


class TestReleaseNotes:
    def test_the_running_version_has_an_extractable_changelog_section(self) -> None:
        # What release.sh guards at cut time, enforced continuously: the version
        # netmon reports must have a CHANGELOG section the tag workflow can turn
        # into release notes. An en-dash or a missing date in the heading breaks
        # the extraction, so this also pins the heading format.
        import netmon

        done = subprocess.run(
            ["sh", str(NOTES_SH), f"v{netmon.__version__}", str(CHANGELOG)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip(), "empty release notes"
