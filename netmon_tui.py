"""Live btop-style dashboard for netmon (--tui). The only module that imports Textual.

Everything stateful/pure lives in netmon (DashboardModel + the event->row helpers);
this file is a thin view: a worker runs the shared capture->process->write loop and
feeds the model, a 10 Hz timer snapshots the model + processor + capture and repaints.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import TYPE_CHECKING, ClassVar, Literal, cast

import structlog
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import DataTable, Footer, SelectionList, Sparkline, Static
from textual.widgets.data_table import RowDoesNotExist
from textual.widgets.selection_list import Selection

from netmon import (
    DIRECTION_VALUES,
    KIND_STYLE,
    KIND_VALUES,
    SCOPE_VALUES,
    SEVERITY_GLYPH,
    SEVERITY_STYLE,
    CopyResult,
    DashboardModel,
    Event,
    EventFilter,
    PacketProcessor,
    Session,
    Severity,
    announce_start,
    assess,
    configure_logging,
    consume,
    copy_to_clipboard,
    event_to_cells,
    event_to_detail,
    open_private_new,
    persist_enabled,
    printable,
)

if TYPE_CHECKING:
    import argparse

log = structlog.get_logger()

# The filter bar's three groups: (widget id, border title, the closed vocabulary). A test
# asserts the lists offer exactly these values — which is also what proves no wire text can
# ever reach the widget.
_FILTER_GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("f-kinds", "kind", KIND_VALUES),
    ("f-dirs", "direction", DIRECTION_VALUES),
    ("f-scopes", "scope", SCOPE_VALUES),
)

_COLUMNS = ("TIME", "KIND", "DIR", "HOST / NAME", "DETAIL")

# Newest events sit at the top; only the most recent slice is drawn (the full
# history is in the JSONL files and the 1000-event ring backs the detail pane).
_DISPLAY_ROWS = 500

# The three feed states, surfaced three ways so a frozen feed is unmissable: a colored
# feed border (CSS class), the feed's border title, and a reverse-video badge in the
# health panel. FOLLOW = live; INSPECT = frozen on a click/scroll; PAUSED = space-held.
_FEED_TITLE = {
    "FOLLOW": "live feed",
    "INSPECT": "live feed — INSPECT · g/Esc to follow",
    "PAUSED": "live feed — PAUSED · space to resume",
}
_MODE_HINT = {
    "FOLLOW": "FOLLOW",
    "INSPECT": "INSPECT g/Esc=follow",
    "PAUSED": "PAUSED space=resume",
}
_MODE_STYLE = {
    "FOLLOW": "bold black on green",
    "INSPECT": "bold black on yellow",
    "PAUSED": "bold white on red",
}


_COL_IDEAL = {"time": 12, "kind": 12, "dir": 3, "host": 40, "detail": 60}
_COL_LOW = {"time": 8, "kind": 6, "dir": 1, "host": 6, "detail": 6}
_COL_ORDER = ("time", "kind", "dir", "host", "detail")


def _fit_column_widths(feed_width: int) -> list[int]:
    # Size the five columns so their total never exceeds the feed's real width —
    # the bug was fixed widths (sum 121) overflowing a ~44-col feed and scrolling
    # HOST/DETAIL off-screen. DataTable clips longer cell text to the column width,
    # so the invariant "no horizontal overflow" holds unconditionally at every size:
    # columns grow toward their ideals with slack, and shrink to one cell each when
    # the terminal is tiny.
    ncols = len(_COLUMNS)
    budget = max(feed_width - 2 * ncols - 1, ncols)  # 2 padding cells/col + margin; >=1 each
    w = dict(_COL_LOW)
    total = sum(w.values())
    if total > budget:  # too tight even for minimums: shave the least essential first
        for name in ("detail", "host", "time", "kind", "dir"):
            give = min(w[name] - 1, total - budget)
            w[name] -= give
            total -= give
            if total <= budget:
                break
    else:  # grow HOST first, then the fixed columns; DETAIL fills the remainder
        extra = budget - total
        w["host"] += min(_COL_IDEAL["host"] - w["host"], extra * 4 // 10)
        for name in ("time", "kind", "dir"):
            grow = min(_COL_IDEAL[name] - w[name], budget - sum(w.values()))
            w[name] += grow
        w["detail"] += budget - sum(w.values())
    return [w[name] for name in _COL_ORDER]


def _styled_cells(event: Event) -> list[Text]:
    style = KIND_STYLE.get(event.kind, "white")
    ts, kind, direction, host, detail = event_to_cells(event)
    # A high-severity finding accents the row's existing DIR cell rather than adding a
    # sixth column: event_to_cells returns exactly five, and _fit_column_widths is built on
    # that count, so a new column would ripple through the layout. This is enough to tell
    # the operator which line the leaks panel is talking about.
    finding = assess(event)
    dir_style = (
        SEVERITY_STYLE[finding.severity]
        if finding is not None and finding.severity is Severity.HIGH
        else style
    )
    return [
        Text(ts, style="dim"),
        Text(kind, style=style),
        Text(direction, style=dir_style),
        Text(host, style=f"bold {style}"),
        Text(detail, style="dim"),
    ]


class FilterBar(Horizontal):
    # `escape` is bound HERE, not on the App. Textual resolves a key along the focused
    # widget's ancestors before reaching the App (Screen._binding_chain), so this shadows the
    # App's escape->follow only while focus is inside the bar, and nowhere else. The App
    # binding is untouched and still follows the newest row when the bar is closed.
    #
    # Deliberately an in-place bar and not a ModalScreen: App.children is only the ACTIVE
    # screen, so while a modal is pushed `query_one("#feed")` raises NoMatches — the 10 Hz
    # _render would early-return for the modal's whole life, model._added would pile up
    # behind it, and the rebuild would raise on close. The bar also changes the feed's
    # HEIGHT, never its width, so column fitting is untouched.
    BINDINGS: ClassVar = [
        Binding("escape", "close_filter", "Close filter"),
        Binding("a", "select_all", "All"),
        Binding("n", "select_none", "None"),
    ]

    def compose(self) -> ComposeResult:
        for wid, title, values in _FILTER_GROUPS:
            # Text(), not str: Selection's prompt is ContentText, so a str is parsed for
            # console markup. These are netmon's own closed vocabularies — no wire text ever
            # reaches this widget — and passing Text keeps that true by construction rather
            # than by luck, in the same spirit as _paint's signature.
            options = [Selection(Text(v), v, initial_state=True) for v in values]
            lst: SelectionList[str] = SelectionList(*options, id=wid)
            lst.border_title = title
            yield lst

    def _focused_list(self) -> SelectionList[str] | None:
        focused = self.app.focused
        return focused if isinstance(focused, SelectionList) else None

    def action_select_all(self) -> None:
        if (lst := self._focused_list()) is not None:
            lst.select_all()

    def action_select_none(self) -> None:
        if (lst := self._focused_list()) is not None:
            lst.deselect_all()

    def action_close_filter(self) -> None:
        cast("NetmonApp", self.app).action_toggle_filter()


class NetmonApp(App[None]):
    CSS = """
    Screen { layout: horizontal; }
    #feed-col { width: 1fr; }
    #side { width: 30; }
    #filters { display: none; height: auto; max-height: 16; }
    #filters SelectionList { width: 1fr; border: round $accent; padding: 0 1; }
    #feed { height: 3fr; border: round $primary; }
    #feed.inspecting { border: round $warning; border-title-color: $warning; }
    #feed.paused { border: round $error; border-title-color: $error; }
    #detail { height: 1fr; border: round $secondary; padding: 0 1; color: $text-muted; }
    #leaks, #hosts, #kinds, #health { border: round $accent; padding: 0 1; }
    #eps { height: 5; border: round $accent; }
    """

    # Name the widget that owns focus instead of letting DOM order decide it. Textual's
    # default AUTO_FOCUS ("*") takes the first focusable widget, which is now a SelectionList
    # inside the (hidden) filter bar — so `escape` would have opened the filter instead of
    # following the feed, and the arrow keys would have driven a bar nobody could see.
    AUTO_FOCUS = "#feed"

    BINDINGS: ClassVar = [
        Binding("q", "quit", "Quit"),
        # Textual clears the terminal ISIG flag, so keyboard Ctrl-C is otherwise a
        # no-op notification; bind it so reflexive Ctrl-C actually quits. (External
        # kill -INT/-TERM is a real signal and still stops capture via run().)
        Binding("ctrl+c", "quit", "Quit", show=False),
        Binding("space", "toggle_pause", "Pause"),
        Binding("f", "toggle_filter", "Filter"),
        Binding("g", "follow", "Follow"),
        Binding("escape", "follow", "Follow", show=False),
        Binding("y", "copy_detail", "Copy"),
    ]

    def __init__(self, session: Session, model: DashboardModel) -> None:
        super().__init__()
        self.session = session
        self.model = model
        self.paused = False
        self.worker_exc: Exception | None = None
        self._filter_idx = 0
        self._displayed: set[str] = set()
        self._selected_key: str | None = None
        self._worker_done = False
        self._widths: list[int] = []
        self._last_feed_width = -1
        self._following = True  # True while pinned to the top, tracking the newest row
        self._frozen: list[tuple[str, Event]] | None = None  # snapshot shown while paused
        self._detail_event: Event | None = None  # event in the detail pane, for `y` copy
        self._indicated_state: tuple[str, str] | None = None  # last (mode, filter) painted

    def compose(self) -> ComposeResult:
        # markup=False on every panel: this app renders data, never markup. _paint is
        # typed to Text, which stops a str at the type level — but a panel added later and
        # updated directly would slip past mypy, and this is what catches that.
        with Horizontal():
            with Vertical(id="feed-col"):
                yield FilterBar(id="filters")
                yield DataTable(id="feed")
                yield Static("(select a row)", id="detail", markup=False)
            with Vertical(id="side"):
                # First in the column: the leaks are the headline, not a footnote.
                yield Static(id="leaks", markup=False)
                yield Static(id="hosts", markup=False)
                yield Static(id="kinds", markup=False)
                yield Sparkline([0.0], id="eps")
                yield Static(id="health", markup=False)
        yield Footer()

    def _paint(self, selector: str, content: Text) -> None:
        # The only place this module calls Static.update. Typed to Text, so a raw str —
        # the crash — cannot reach a panel without mypy saying so.
        self.query_one(selector, Static).update(content)

    def on_mount(self) -> None:
        table = self.query_one("#feed", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        for wid, title in (
            ("#feed", "live feed"),
            ("#detail", "detail"),
            ("#leaks", "leaks"),
            ("#hosts", "top hosts"),
            ("#kinds", "by kind"),
            ("#eps", "events/sec"),
            ("#health", "capture"),
        ):
            self.query_one(wid).border_title = title
        self._relayout(table)  # columns are (re)sized to the feed's actual width
        # One async worker on this app's own loop runs the shared consume loop; no
        # thread => the model ring and rate bucketer need no locks.
        self.run_worker(self._run_consume(), name="consume", exclusive=True)
        self.set_interval(0.1, self._render)

    async def _run_consume(self) -> None:
        try:
            await consume(self.session, self.model.add_event)
        except Exception as exc:  # surfaced by run_dashboard as a loud nonzero exit
            self.worker_exc = exc
        finally:
            # Worker completed for ANY reason (replay EOF, capture.stop() from a
            # signal, or user quit): always exit so run()'s finally writes the
            # summary. Without this a live --tui killed by a signal hangs forever.
            self._worker_done = True
            self.exit()

    # --- rendering -----------------------------------------------------------
    # Follow/inspect model (like `less +F`): while FOLLOWING, the feed live-updates
    # with the newest event pinned at the top. Scrolling down or moving the cursor
    # off the top switches to INSPECT — the view freezes on a snapshot so history can
    # be read without it snapping back — until the user presses `g` to follow again.
    # The mode is explicit, so a redraw resetting the scroll offset can't flip it.
    def _render(self) -> None:
        # A tick that races shutdown must do nothing at all. The guard has to wrap the WHOLE
        # tick, not just the first lookup: _render_panels goes on to query #hosts, #kinds,
        # #eps and #health, and the widget tree can vanish between any two of them. Guarding
        # only #feed left a window that failed roughly one run in six — and since pytest is
        # this project's only gate, a flaky gate is a broken one.
        if not self.is_running:
            return
        try:
            self._render_tick()
        except NoMatches:
            return  # teardown began mid-tick; the widget tree is going away

    def _render_tick(self) -> None:
        table = self.query_one("#feed", DataTable)
        added, evicted = self.model.drain_new()  # always drain so deltas don't pile up
        if self._following and table.scroll_offset.y != 0:
            self._enter_inspect()  # scrolled away from the top (wheel / page keys)
        # Size to the scrollable region, not the widget: when rows fill the viewport a
        # vertical scrollbar appears and steals cell columns with no width change, so
        # keying off size.width would leave the columns overflowing (HOST/DETAIL clipped
        # off the right). Watching the region refits the moment the scrollbar appears.
        width = table.scrollable_content_region.width
        if width > 0 and width != self._last_feed_width:
            self._last_feed_width = width  # resized, or a scrollbar (dis)appeared
            self._relayout(table)
        elif self._following and not self.paused and (added or evicted):
            self._rebuild_feed()
        self._render_panels()

    def _enter_inspect(self) -> None:
        # Freeze on what's shown now so a later resize/filter redraws the same events,
        # not the live tail. Snapshot once; paused already holds one. Toast only on the
        # FOLLOW->inspect transition: not while already PAUSED (whose own badge shows the
        # freeze), and not on every arrow key that re-enters inspect.
        if self._mode() == "FOLLOW":
            self.notify("feed frozen (INSPECT) — press g or Esc to follow")
        self._following = False
        if self._frozen is None:
            self._frozen = self.model.newest_first()

    def _resume_follow(self) -> None:
        # Following the newest resumes the live feed, which means clearing pause too —
        # otherwise the state is paused+following with a lying "PAUSED" panel.
        self._following = True
        self.paused = False
        self._frozen = None
        self._selected_key = None
        self._rebuild_feed()

    def _relayout(self, table: DataTable) -> None:
        # Refit the columns to the feed's current width and redraw. DataTable has no
        # live column-resize, so columns are cleared and re-added, then rows rebuilt.
        # Uses the scrollable region (excludes the vertical scrollbar) so columns fit
        # the real cell area and never overflow. While paused the redraw uses the
        # frozen snapshot, so resizing can't quietly un-freeze the feed.
        self._widths = _fit_column_widths(table.scrollable_content_region.width)
        table.clear(columns=True)
        self._displayed.clear()
        for label, width in zip(_COLUMNS, self._widths, strict=True):
            table.add_column(label, width=width)
        self._rebuild_feed()

    def _resync_cursor(self, table: DataTable) -> None:
        key = self._selected_key
        if key is None:
            return
        try:
            table.move_cursor(row=table.get_row_index(key), scroll=False)
        except RowDoesNotExist:
            self._selected_key = None
            self._set_detail(None, "(expired)")

    def _set_detail(self, event: Event | None, placeholder: str = "(select a row)") -> None:
        # Single source for the detail pane: tracks the shown event so `y` yanks exactly
        # what is on screen, and never leaves a stale event pinned when the pane clears.
        self._detail_event = event
        self._paint("#detail", Text(event_to_detail(event) if event is not None else placeholder))

    def _mode(self) -> Literal["FOLLOW", "INSPECT", "PAUSED"]:
        return "PAUSED" if self.paused else ("FOLLOW" if self._following else "INSPECT")

    def _refresh_mode_indicator(self, mode: str) -> None:
        # Paint the feed border + title to match the mode and the active filter; only on a
        # change so the 10 Hz tick doesn't refresh the border every frame. The filter belongs
        # here for the same reason the mode does: a feed that is hiding events must never be
        # mistaken for a quiet network.
        label = self.model.filter.label()
        state = (mode, label)
        if state == self._indicated_state:
            return
        self._indicated_state = state
        feed = self.query_one("#feed", DataTable)
        feed.set_class(mode == "PAUSED", "paused")
        feed.set_class(mode == "INSPECT", "inspecting")
        title = _FEED_TITLE[mode]
        # Text, not str: border_title runs a str through markup parsing, and label() can carry
        # a host substring the operator typed.
        feed.border_title = Text(
            title if self.model.filter.is_unconstrained() else f"{title} · filter: {label}"
        )

    def _render_leaks(self, proc: PacketProcessor) -> None:
        rows = proc.findings.top(10)
        panel = Text()
        for i, (finding, count) in enumerate(rows):
            if i:
                panel.append("\n")
            style = SEVERITY_STYLE[finding.severity]
            panel.append(f"{SEVERITY_GLYPH[finding.severity]} ", style=style)
            # subject is wire-derived — a queried name, an SNI, an address — so it goes
            # through printable() before it reaches a terminal, exactly like every other
            # panel that shows something off the wire. This is the hole printable() exists
            # to close, not belt-and-braces.
            panel.append(f"{printable(finding.subject)[:18]:<18}", style=style)
            panel.append(f"{count:>5}", style="dim")
        if not rows:
            # An empty panel must not read as an assurance. netmon has no notion of
            # "unusual": nothing matching a known shape was recorded, which is a smaller
            # claim than "nothing leaked".
            panel.append("(none recorded)", style="dim")
        self._paint("#leaks", panel)
        counts = proc.findings.by_severity()
        tally = " ".join(
            f"{counts[str(sev)]}{str(sev)[0].upper()}"
            for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
            if counts.get(str(sev))
        )
        self.query_one("#leaks", Static).border_title = Text(
            f"leaks · {tally}" if tally else "leaks"
        )

    def _render_panels(self) -> None:
        proc = self.session.processor
        self._render_leaks(proc)
        hosts = proc.remote_hosts.most_common(12)
        # remote_hosts keys are DNS/SNI-learned names straight off the wire, and they never
        # pass through the feed's cell projection — so they are scrubbed here.
        self._paint(
            "#hosts",
            Text("\n".join(f"{c:>5}  {printable(h)}" for h, c in hosts) or "(none yet)"),
        )
        counts = proc.event_counts
        self._paint(
            "#kinds",
            Text(
                "\n".join(f"{counts[k]:>6}  {k}" for k in sorted(counts, key=lambda k: -counts[k]))
                or "(none yet)"
            ),
        )
        self.query_one("#eps", Sparkline).data = self.model.rate_series() or [0.0]
        st = self.session.capture.stats()
        kd = "n/a" if st.kernel_dropped is None else st.kernel_dropped
        mode = self._mode()
        health = Text(
            f"packets {proc.coverage.packets}\nqueue   {st.queued}\n"
            f"udrop   {st.userspace_dropped}\nkdrop   {kd}\n"
        )
        health.append(_MODE_HINT[mode], style=_MODE_STYLE[mode])
        self._paint("#health", health)
        self._refresh_mode_indicator(mode)

    def _rebuild_feed(self) -> None:
        # Redraw the feed newest-first (latest at the top, btop-style), applying the
        # active filter, capped at _DISPLAY_ROWS. Rebuilding — rather than appending —
        # is required because DataTable can only add rows at the bottom. While paused
        # the source is the frozen snapshot so live events stay hidden until resume.
        table = self.query_one("#feed", DataTable)
        # A snapshot exists exactly while paused or inspecting; draw it so a resize or
        # filter can't quietly reveal the live tail and lose the reader's place.
        source = self._frozen if self._frozen is not None else self.model.newest_first()
        table.clear()
        self._displayed.clear()
        with self.batch_update():
            for key, event in source:
                if self.model.passes(event):
                    table.add_row(*_styled_cells(event), key=key)
                    self._displayed.add(key)
                    if len(self._displayed) >= _DISPLAY_ROWS:
                        break
        # Reconcile the selection with the redrawn rows. While following there is no
        # sticky selection (the top row is auto-highlighted), so this only matters on a
        # filter/pause redraw: re-assert a surviving selection, or expire the detail
        # pane rather than let it show a stale event.
        if not self._displayed:
            self._selected_key = None
            # "nothing matched" and "nothing happened" are different facts, and an operator
            # who unticked every box must not read the second when the first is true.
            empty = (
                "(no events)"
                if self.model.filter.is_unconstrained()
                else ("(no rows match the filter)")
            )
            self._set_detail(None, empty)
        elif self._selected_key is None:
            pass
        elif self._selected_key in self._displayed:
            self._resync_cursor(table)
        else:
            self._selected_key = None
            self._set_detail(None, "(expired)")

    # --- events & actions ----------------------------------------------------
    def on_data_table_row_highlighted(self, message: DataTable.RowHighlighted) -> None:
        key = message.row_key.value
        # Row 0 is DataTable's own auto-highlight on redraw of the newest row — not a
        # user pick, so following continues and no selection sticks. A highlight on any
        # other row means the user navigated with the keyboard/mouse: switch to inspect
        # and pin that selection so the feed stops chasing the top.
        if message.cursor_row != 0:
            self._enter_inspect()
            self._selected_key = key
        self._set_detail(self.model.event_by_key(key) if key is not None else None)

    async def action_quit(self) -> None:
        # Stop capture and let the consume worker finish and call exit(); this runs
        # LiveCapture's finally (stop sniffer, harvest tp_drops, close sockets) before
        # run()'s finally writes the summary. If the worker already ended, exit now.
        if self._worker_done:
            self.exit()
        else:
            self.session.capture.stop()

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        if self.paused:
            if self._frozen is None:  # freeze the visible set (unless already inspecting)
                self._frozen = self.model.newest_first()
        elif self._following:  # resume live only if not still scrolled into history
            self._frozen = None
        self._rebuild_feed()

    def action_toggle_filter(self) -> None:
        # `f` opens AND closes: SelectionList binds only `space`, so ordinary letter keys
        # still reach the App while the bar has focus.
        bar = self.query_one("#filters", FilterBar)
        if bar.display:
            self.query_one("#feed", DataTable).focus()  # focus out before hiding
            bar.display = False
        else:
            bar.display = True
            self.query_one("#f-kinds", SelectionList).focus()

    def _selected_filter(self) -> EventFilter:
        def chosen(wid: str) -> frozenset[str]:
            return frozenset(self.query_one(wid, SelectionList).selected)

        return EventFilter(
            kinds=chosen("#f-kinds"),
            directions=chosen("#f-dirs"),
            scopes=chosen("#f-scopes"),
            host=self.model.filter.host,
        )

    def on_selection_list_selected_changed(
        self, _message: SelectionList.SelectedChanged[str]
    ) -> None:
        # One handler for all three lists: the filter is rebuilt from the three selections,
        # so there is no per-list state to keep in sync. Re-filters the live tail while
        # following, or the frozen snapshot while paused/inspecting — _rebuild_feed already
        # draws from _frozen, so filtering never yanks a reader off their scroll position.
        self.model.filter = self._selected_filter()
        self._rebuild_feed()

    def action_follow(self) -> None:
        self._resume_follow()
        self.notify("following newest")

    def _term_write(self, seq: str) -> None:
        # Raw escape bytes to the terminal, for the OSC 52 fallback. Textual exposes no
        # public raw-write API, so we reuse the private driver its own copy_to_clipboard
        # writes through. Invoked from the clipboard worker thread, so hop back onto the
        # event loop via call_from_thread — a driver write must not race the compositor.
        # The guard covers the pre-mount / post-shutdown window when there is no driver.
        driver = self._driver
        if driver is not None:
            self.call_from_thread(driver.write, seq)

    async def action_copy_detail(self) -> None:
        # Yank the selected packet's detail (the text shown in the pane) to the system
        # clipboard. A local session copies via a clipboard CLI (confirmable, bypasses
        # tmux); otherwise it falls back to OSC 52 (best-effort). The toast reflects which
        # happened instead of always claiming success. The CLI spawn can block for up to a
        # couple seconds, so it runs off the event loop to keep the TUI responsive. Works
        # whenever a packet is selected; the guard covers the nothing-picked case.
        if self._detail_event is None:
            self.notify("no packet selected", severity="warning")
            return
        text = event_to_detail(self._detail_event)
        result = await asyncio.to_thread(
            copy_to_clipboard, text, env=os.environ, write=self._term_write
        )
        emit = log.warning if result is CopyResult.FAILED else log.info
        emit("clipboard_copy", result=result.value, chars=len(text))
        if result is CopyResult.LOCAL:
            self.notify("copied packet detail to clipboard")
        elif result is CopyResult.TERMINAL:
            self.notify(
                "copy sent to terminal (OSC 52) — needs terminal/tmux clipboard support",
                timeout=6,
            )
        else:
            self.notify("copy failed: no clipboard available", severity="warning")


async def run_dashboard(session: Session, args: argparse.Namespace) -> None:
    # Redirect structlog to a file while Textual owns stdout, so a stray log line
    # can't garble the compositor; restore on the way out so run()'s final
    # capture_stopped prints cleanly after the terminal is released. Headless when
    # there is no tty (tests) — production reaches here only past main()'s tty guard.
    app = NetmonApp(session, DashboardModel())
    # --log persists diagnostics next to the JSONL record; without it the run is
    # ephemeral so structlog goes to the void — never stdout, which Textual owns.
    if persist_enabled(args):
        diag = open_private_new(session.out_dir / "netmon.log")
    else:
        diag = os.fdopen(os.open(os.devnull, os.O_WRONLY), "w", encoding="utf-8")
    with diag as fp:
        configure_logging(stream=fp)
        announce_start(args, session)  # capture_started/replay_started -> the log file
        try:
            await app.run_async(headless=not sys.stdout.isatty())
        finally:
            configure_logging()
    if app.worker_exc is not None:
        raise app.worker_exc
    if app.return_code not in (0, None):
        raise RuntimeError(f"tui exited with error (return_code={app.return_code})")
