import base64
import subprocess
from collections.abc import Callable
from types import SimpleNamespace

from netmon import CopyResult, copy_to_clipboard


class RunRecorder:
    # Stands in for subprocess.run: records each call and returns a fake completed
    # process (or raises), so no clipboard CLI is ever actually spawned.
    def __init__(self, returncode: int = 0, exc: Exception | None = None) -> None:
        self.returncode = returncode
        self.exc = exc
        self.calls: list[SimpleNamespace] = []

    def __call__(self, argv, *, input, capture_output, timeout):
        self.calls.append(SimpleNamespace(argv=argv, input=input, timeout=timeout))
        if self.exc is not None:
            raise self.exc
        return SimpleNamespace(returncode=self.returncode, stdout=b"", stderr=b"")


def which_of(*present: str):
    table = {name: f"/usr/bin/{name}" for name in present}
    return lambda name: table.get(name)


def collect_writes() -> tuple[list[str], Callable[[str], None]]:
    seen: list[str] = []
    return seen, seen.append


def osc52_text(seq: str) -> str:
    assert seq.startswith("\x1b]52;c;")
    assert seq.endswith("\a")
    return base64.b64decode(seq[len("\x1b]52;c;") : -1]).decode()


def test_wayland_uses_wl_copy_and_confirms_without_touching_terminal() -> None:
    run = RunRecorder(returncode=0)
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "hello",
        env={"WAYLAND_DISPLAY": "wayland-0"},
        write=write,
        run=run,
        which=which_of("wl-copy", "xclip"),
    )
    assert result is CopyResult.LOCAL
    assert run.calls[0].argv == ["/usr/bin/wl-copy"]
    assert run.calls[0].input == b"hello"
    assert writes == []  # a confirmed CLI copy never falls through to OSC 52


def test_x11_prefers_xclip_clipboard_selection() -> None:
    run = RunRecorder()
    result = copy_to_clipboard(
        "data", env={"DISPLAY": ":0"}, write=None, run=run, which=which_of("xclip", "xsel")
    )
    assert result is CopyResult.LOCAL
    assert run.calls[0].argv == ["/usr/bin/xclip", "-selection", "clipboard"]


def test_x11_falls_back_to_xsel_when_no_xclip() -> None:
    run = RunRecorder()
    result = copy_to_clipboard(
        "data", env={"DISPLAY": ":0"}, write=None, run=run, which=which_of("xsel")
    )
    assert result is CopyResult.LOCAL
    assert run.calls[0].argv == ["/usr/bin/xsel", "--clipboard", "--input"]


def test_macos_uses_pbcopy() -> None:
    run = RunRecorder()
    result = copy_to_clipboard("x", env={}, write=None, run=run, which=which_of("pbcopy"))
    assert result is CopyResult.LOCAL
    assert run.calls[0].argv == ["/usr/bin/pbcopy"]


def test_wsl_uses_clip_exe() -> None:
    run = RunRecorder()
    result = copy_to_clipboard("x", env={}, write=None, run=run, which=which_of("clip.exe"))
    assert result is CopyResult.LOCAL
    assert run.calls[0].argv == ["/usr/bin/clip.exe"]


def test_ssh_session_skips_local_cli_and_emits_osc52() -> None:
    # Over SSH the local clipboard belongs to the wrong machine; only OSC 52 can reach
    # the user's terminal, so the CLI path must be bypassed entirely.
    run = RunRecorder()
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "secret",
        env={
            "SSH_CONNECTION": "1.2.3.4 22 5.6.7.8 22",
            "DISPLAY": ":0",
            "WAYLAND_DISPLAY": "wayland-0",
        },
        write=write,
        run=run,
        which=which_of("wl-copy", "xclip"),
    )
    assert result is CopyResult.TERMINAL
    assert run.calls == []
    assert osc52_text(writes[0]) == "secret"


def test_ssh_tty_alone_marks_session_remote() -> None:
    run = RunRecorder()
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "x",
        env={"SSH_TTY": "/dev/pts/3", "WAYLAND_DISPLAY": "wayland-0"},
        write=write,
        run=run,
        which=which_of("wl-copy"),
    )
    assert result is CopyResult.TERMINAL
    assert run.calls == []
    assert osc52_text(writes[0]) == "x"


def test_no_local_sink_falls_back_to_osc52() -> None:
    writes, write = collect_writes()
    result = copy_to_clipboard("x", env={}, write=write, run=RunRecorder(), which=which_of())
    assert result is CopyResult.TERMINAL
    assert osc52_text(writes[0]) == "x"


def test_no_sink_and_no_terminal_writer_fails() -> None:
    result = copy_to_clipboard("x", env={}, write=None, run=RunRecorder(), which=which_of())
    assert result is CopyResult.FAILED


def test_cli_nonzero_exit_falls_back_to_osc52() -> None:
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "x",
        env={"WAYLAND_DISPLAY": "wayland-0"},
        write=write,
        run=RunRecorder(returncode=1),
        which=which_of("wl-copy"),
    )
    assert result is CopyResult.TERMINAL
    assert osc52_text(writes[0]) == "x"


def test_cli_raising_oserror_falls_back_to_osc52() -> None:
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "x",
        env={"WAYLAND_DISPLAY": "wayland-0"},
        write=write,
        run=RunRecorder(exc=OSError("boom")),
        which=which_of("wl-copy"),
    )
    assert result is CopyResult.TERMINAL
    assert osc52_text(writes[0]) == "x"


def test_cli_timeout_falls_back_to_osc52() -> None:
    # A hung clipboard tool raises TimeoutExpired (a SubprocessError); it must be caught
    # and degrade to OSC 52, never propagate out of the copy.
    writes, write = collect_writes()
    result = copy_to_clipboard(
        "x",
        env={"WAYLAND_DISPLAY": "wayland-0"},
        write=write,
        run=RunRecorder(exc=subprocess.TimeoutExpired("wl-copy", 2)),
        which=which_of("wl-copy"),
    )
    assert result is CopyResult.TERMINAL
    assert osc52_text(writes[0]) == "x"


def test_unicode_round_trips_through_osc52() -> None:
    writes, write = collect_writes()
    text = "π λ 数据 — café"
    result = copy_to_clipboard(text, env={}, write=write, run=RunRecorder(), which=which_of())
    assert result is CopyResult.TERMINAL
    assert osc52_text(writes[0]) == text
