"""Live btop-style dashboard for netmon (--tui). The only module that imports Textual.

Everything stateful/pure lives in netmon (DashboardModel + the event->row helpers);
this file is a thin view: a worker runs the shared capture->process->write loop and
feeds the model, a 10 Hz timer snapshots the model + processor + capture and repaints.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import DataTable, Footer, Sparkline, Static
from textual.widgets.data_table import RowDoesNotExist

from netmon import (
    KIND_STYLE,
    DashboardModel,
    Event,
    Session,
    announce_start,
    configure_logging,
    consume,
    event_to_cells,
    open_private_new,
)

if TYPE_CHECKING:
    import argparse

# `f` cycles the feed through these substring filters (matched against kind / host /
# detail by DashboardModel.passes); None shows everything.
_FILTERS: list[str | None] = [None, "dns", "tls", "http", "flow"]

_COLUMNS = ("TIME", "KIND", "DIR", "HOST / NAME", "DETAIL")

# Newest events sit at the top; only the most recent slice is drawn (the full
# history is in the JSONL files and the 1000-event ring backs the detail pane).
_DISPLAY_ROWS = 500


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
    return [
        Text(ts, style="dim"),
        Text(kind, style=style),
        Text(direction, style=style),
        Text(host, style=f"bold {style}"),
        Text(detail, style="dim"),
    ]


def _format_detail(event: Event) -> str:
    data = event.model_dump(exclude_none=True)
    lines = [f"{event.kind}   {event.ts}"]
    lines += [f"  {k}: {v}" for k, v in data.items() if k not in ("kind", "ts")]
    return "\n".join(lines)


class NetmonApp(App[None]):
    CSS = """
    Screen { layout: horizontal; }
    #feed-col { width: 1fr; }
    #side { width: 30; }
    #feed { height: 3fr; border: round $primary; }
    #detail { height: 1fr; border: round $secondary; padding: 0 1; color: $text-muted; }
    #hosts, #kinds, #health { border: round $accent; padding: 0 1; }
    #eps { height: 5; border: round $accent; }
    """

    BINDINGS: ClassVar = [
        Binding("q", "quit", "Quit"),
        # Textual clears the terminal ISIG flag, so keyboard Ctrl-C is otherwise a
        # no-op notification; bind it so reflexive Ctrl-C actually quits. (External
        # kill -INT/-TERM is a real signal and still stops capture via run().)
        Binding("ctrl+c", "quit", "Quit", show=False),
        Binding("space", "toggle_pause", "Pause"),
        Binding("f", "cycle_filter", "Filter"),
        Binding("g", "follow", "Follow"),
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

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="feed-col"):
                yield DataTable(id="feed")
                yield Static("(select a row)", id="detail")
            with Vertical(id="side"):
                yield Static(id="hosts")
                yield Static(id="kinds")
                yield Sparkline([0.0], id="eps")
                yield Static(id="health")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#feed", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        for wid, title in (
            ("#feed", "live feed"),
            ("#detail", "detail"),
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
        try:
            table = self.query_one("#feed", DataTable)
        except NoMatches:
            return  # a scheduled tick raced app shutdown; the widget tree is gone
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
        # not the live tail. Snapshot once; paused already holds one.
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
            self.query_one("#detail", Static).update("(expired)")

    def _render_panels(self) -> None:
        proc = self.session.processor
        hosts = proc.remote_hosts.most_common(12)
        self.query_one("#hosts", Static).update(
            "\n".join(f"{c:>5}  {h}" for h, c in hosts) or "(none yet)"
        )
        counts = proc.event_counts
        self.query_one("#kinds", Static).update(
            "\n".join(f"{counts[k]:>6}  {k}" for k in sorted(counts, key=lambda k: -counts[k]))
            or "(none yet)"
        )
        self.query_one("#eps", Sparkline).data = self.model.rate_series() or [0.0]
        st = self.session.capture.stats()
        kd = "n/a" if st.kernel_dropped is None else st.kernel_dropped
        mode = "PAUSED" if self.paused else ("FOLLOW" if self._following else "INSPECT g=follow")
        self.query_one("#health", Static).update(
            f"packets {proc.coverage.packets}\nqueue   {st.queued}\n"
            f"udrop   {st.userspace_dropped}\nkdrop   {kd}\n{mode}"
        )

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
            self.query_one("#detail", Static).update("(no events)")
        elif self._selected_key is None:
            pass
        elif self._selected_key in self._displayed:
            self._resync_cursor(table)
        else:
            self._selected_key = None
            self.query_one("#detail", Static).update("(expired)")

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
        event = self.model.event_by_key(key) if key is not None else None
        self.query_one("#detail", Static).update(
            _format_detail(event) if event is not None else "(select a row)"
        )

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

    def action_cycle_filter(self) -> None:
        # Re-filters the live tail while following, or the frozen snapshot while paused
        # or inspecting — so filtering never yanks a reader off their scroll position.
        self._filter_idx = (self._filter_idx + 1) % len(_FILTERS)
        self.model.filter = _FILTERS[self._filter_idx]
        self._rebuild_feed()
        self.notify(f"filter: {self.model.filter or 'all'}")

    def action_follow(self) -> None:
        self._resume_follow()
        self.notify("following newest")


async def run_dashboard(session: Session, args: argparse.Namespace) -> None:
    # Redirect structlog to a file while Textual owns stdout, so a stray log line
    # can't garble the compositor; restore on the way out so run()'s final
    # capture_stopped prints cleanly after the terminal is released. Headless when
    # there is no tty (tests) — production reaches here only past main()'s tty guard.
    app = NetmonApp(session, DashboardModel())
    with open_private_new(session.out_dir / "netmon.log") as fp:
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
