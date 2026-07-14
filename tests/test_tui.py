import argparse
import asyncio
from pathlib import Path

import pytest

pytest.importorskip("textual")

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from structlog.testing import capture_logs
from textual.widgets import DataTable, SelectionList, Static

import netmon_tui
from netmon import (
    DIRECTION_VALUES,
    KIND_VALUES,
    SCOPE_VALUES,
    CaptureStats,
    DashboardModel,
    DnsQueryEvent,
    HttpEvent,
    JsonlWriter,
    PacketProcessor,
    Session,
    TlsSniEvent,
    event_to_detail,
)
from netmon_tui import FilterBar, NetmonApp, run_dashboard

TS = "2025-07-02T23:46:40.123+00:00"
PKT_TIME = 1751500000.123


class FakeCapture:
    # A Capture that yields the given packets then idles until stop() — enough to
    # drive the App without opening a raw socket. With no packets it blocks so the
    # App stays up while a test drives the model directly.
    def __init__(self, packets: tuple = ()) -> None:
        self._packets = list(packets)
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> CaptureStats:
        return CaptureStats(
            queued=0, userspace_dropped=0, kernel_dropped=None, kernel_delivered=None
        )

    async def packets(self):
        for pkt in self._packets:
            if self._stop.is_set():
                return
            yield pkt
        await self._stop.wait()


def make_session(tmp_path: Path, packets: tuple = ()) -> Session:
    out_dir = tmp_path / "run"
    return Session(
        out_dir=out_dir,
        processor=PacketProcessor(local_ips=frozenset()),
        writer=JsonlWriter(out_dir),
        capture=FakeCapture(packets),
    )


def q(name: str) -> DnsQueryEvent:
    return DnsQueryEvent(
        ts=TS, src="10.0.0.5", dst="10.0.0.1", transport="udp", qname=name, qtype="A"
    )


def sni(name: str) -> TlsSniEvent:
    return TlsSniEvent(ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=443, sni=name, alpn=["h2"])


def http_with_path(path: str) -> HttpEvent:
    return HttpEvent(
        ts=TS, src="10.0.0.5", dst="1.2.3.4", dport=80, method="GET", path=path, host="x.example"
    )


class TestNetmonAppFeed:
    async def test_mounts_with_five_columns(self, tmp_path: Path) -> None:
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        async with app.run_test():
            assert len(app.query_one("#feed", DataTable).columns) == 5
            await app.action_quit()

    async def test_events_render_into_feed(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            model.add_event(q("example.com"))
            model.add_event(sni("github.com"))
            app._render()
            assert app.query_one("#feed", DataTable).row_count == 2
            await app.action_quit()

    async def test_row_highlight_updates_detail_pane(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(q("example.com"))
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            assert "dns_query" in str(app.query_one("#detail", Static).render())
            assert "example.com" in str(app.query_one("#detail", Static).render())
            await app.action_quit()


class TestNetmonAppHardening:
    async def test_newest_event_appears_at_the_top(self, tmp_path: Path) -> None:
        # btop-style: the latest row is at the top, not accumulating at the bottom.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(q("oldest.example.com"))
            model.add_event(q("newest.example.com"))
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
            assert "newest.example.com" in str(table.get_row_at(0)[3])
            assert "oldest.example.com" in str(table.get_row_at(table.row_count - 1)[3])
            await app.action_quit()

    async def test_columns_fit_every_terminal_width(self, tmp_path: Path) -> None:
        # The original bug: fixed widths (sum 121) overflowed the feed and scrolled
        # HOST/DETAIL off-screen. Column widths must always fit without overflow.
        from netmon_tui import _fit_column_widths

        for feed_width in range(30, 220):
            widths = _fit_column_widths(feed_width)
            assert min(widths) >= 1
            assert sum(widths) + 2 * len(widths) <= feed_width  # + per-column padding

    async def test_no_horizontal_overflow_when_scrollbar_present(self, tmp_path: Path) -> None:
        # Regression: once enough rows arrive for a vertical scrollbar, it steals cell
        # width; columns sized to the full widget width then overflow and the right
        # columns (HOST/DETAIL) get clipped off. Columns must fit the *scrollable*
        # region, so no horizontal scrollbar ever appears.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(120, 16)) as pilot:
            for i in range(60):  # far more rows than the viewport -> vertical scrollbar
                model.add_event(q(f"h{i}.example.com"))
            table = app.query_one("#feed", DataTable)
            # The scrollbar materialises asynchronously; the columns refit on the next
            # render once the region reflects it. Pump render/pause until it settles so
            # the assertion isn't racing that reflow (it converges in 1-2 frames).
            for _ in range(10):
                app._render()
                await pilot.pause()
                if (
                    table.show_vertical_scrollbar
                    and table.virtual_size.width <= table.scrollable_content_region.width
                ):
                    break
            assert table.show_vertical_scrollbar is True  # precondition for the bug
            assert table.virtual_size.width <= table.scrollable_content_region.width
            assert table.show_horizontal_scrollbar is False  # nothing clipped off the right
            await app.action_quit()

    async def test_narrow_terminal_shows_all_columns(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(70, 24)) as pilot:
            model.add_event(q("a-very-long-hostname.example.com"))
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
            assert len(table.columns) == 5
            assert table.virtual_size.width <= table.size.width  # nothing scrolled off
            await app.action_quit()

    async def test_resize_while_paused_keeps_frozen_view(self, tmp_path: Path) -> None:
        # A resize refits columns via _relayout; while paused it must redraw the frozen
        # snapshot, not silently catch the feed up to the live model.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 24)) as pilot:
            model.add_event(q("a.com"))
            app._render()
            app.action_toggle_pause()
            model.add_event(q("b.com"))  # arrives while paused
            await pilot.resize_terminal(80, 24)
            app._render()
            await pilot.pause()
            assert app.paused is True
            assert app.query_one("#feed", DataTable).row_count == 1  # still frozen at 1
            await app.action_quit()

    async def test_scroll_down_freezes_then_g_resumes_follow(self, tmp_path: Path) -> None:
        # Scrolling down to read history freezes the feed; pressing `g` (follow) resumes
        # the live tail — the view never snaps back mid-read.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 20)) as pilot:
            for i in range(40):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
            table.scroll_to(y=10, animate=False)
            app._render()  # detects the scroll -> INSPECT
            await pilot.pause()
            assert app._following is False
            top_before = str(table.get_row_at(0)[3])
            model.add_event(q("arrived-while-reading.example.com"))
            app._render()
            await pilot.pause()
            assert str(table.get_row_at(0)[3]) == top_before  # frozen: no live catch-up
            await pilot.press("g")  # follow again
            model.add_event(q("newest.example.com"))
            app._render()
            await pilot.pause()
            assert app._following is True
            assert "newest.example.com" in str(table.get_row_at(0)[3])

    async def test_resize_while_scrolled_stays_frozen(self, tmp_path: Path) -> None:
        # A resize refits columns via _relayout; while inspecting (scrolled, not paused)
        # it must redraw the frozen snapshot, not silently reveal the live tail.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 20)) as pilot:
            for i in range(40):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
            table.scroll_to(y=10, animate=False)
            app._render()  # -> INSPECT
            await pilot.pause()
            model.add_event(q("arrived-while-scrolled.example.com"))
            await pilot.resize_terminal(80, 20)
            app._render()
            await pilot.pause()
            names = [str(table.get_row_at(i)[3]) for i in range(table.row_count)]
            assert "arrived-while-scrolled.example.com" not in names  # not un-frozen
            await app.action_quit()

    async def test_filter_while_scrolled_stays_frozen(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 20)) as pilot:
            for i in range(40):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
            table.scroll_to(y=10, animate=False)
            app._render()  # -> INSPECT
            await pilot.pause()
            model.add_event(q("arrived-while-scrolled.example.com"))
            # Re-filtering must redraw the frozen SNAPSHOT, not the live tail — every dns
            # kind still matches here, so a row that appears could only have come from the
            # tail, which would yank the reader off their scroll position.
            kinds = app.query_one("#f-kinds", SelectionList)
            kinds.deselect_all()
            for k in KIND_VALUES:
                if k.startswith("dns_"):
                    kinds.select(k)
            await pilot.pause()
            names = [str(table.get_row_at(i)[3]) for i in range(table.row_count)]
            assert "arrived-while-scrolled.example.com" not in names
            await app.action_quit()

    async def test_arrow_navigation_persists_selection(self, tmp_path: Path) -> None:
        # A short feed never scrolls (offset stays 0); moving the cursor off the top row
        # must still switch to inspect and hold the selection, not be reset by the timer.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 24)) as pilot:
            for i in range(5):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            app.query_one("#feed", DataTable).move_cursor(row=2)  # user navigates down
            await pilot.pause()
            assert app._following is False
            selected = app._selected_key
            assert selected is not None
            model.add_event(q("newer.example.com"))
            app._render()
            await pilot.pause()
            assert app._selected_key == selected  # selection survives the live tick
            await app.action_quit()

    async def test_pause_freezes_then_resume_rebuilds(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            model.add_event(q("a"))
            app._render()
            app.action_toggle_pause()
            assert app.paused is True
            model.add_event(q("b"))  # arrives while paused
            app._render()
            assert app.query_one("#feed", DataTable).row_count == 1  # frozen
            app.action_toggle_pause()  # resume rebuilds from the ring
            assert app.query_one("#feed", DataTable).row_count == 2
            await app.action_quit()

    async def test_filter_bar_is_hidden_at_startup_and_passes_everything(
        self, tmp_path: Path
    ) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            assert app.query_one("#filters", FilterBar).display is False
            assert model.filter.is_unconstrained()
            await app.action_quit()

    async def test_the_feed_owns_focus_at_startup_not_the_hidden_filter_bar(
        self, tmp_path: Path
    ) -> None:
        # Regression: Textual's default AUTO_FOCUS takes the first focusable widget, and the
        # filter bar's first list now precedes the feed in the DOM. Focus landed on a
        # SelectionList nobody could see — so `escape` opened the filter instead of following,
        # and the arrow keys drove the hidden bar rather than the feed.
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        async with app.run_test():
            assert isinstance(app.focused, DataTable)
            await app.action_quit()

    async def test_f_opens_and_closes_the_bar(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            bar = app.query_one("#filters", FilterBar)
            await pilot.press("f")
            assert bar.display is True
            assert isinstance(app.focused, SelectionList)
            # SelectionList binds only `space`, so `f` still reaches the App and closes it.
            await pilot.press("f")
            assert bar.display is False
            await app.action_quit()

    async def test_escape_closes_the_bar_without_snapping_back_to_follow(
        self, tmp_path: Path
    ) -> None:
        # `escape` is already the App's follow key. Binding it on the bar shadows the App's
        # only while focus is inside the bar — so closing the filter must NOT also yank an
        # inspecting reader back to the newest row.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 20)) as pilot:
            for i in range(40):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            app.query_one("#feed", DataTable).scroll_to(y=10, animate=False)
            app._render()  # -> INSPECT
            await pilot.pause()
            assert app._following is False

            await pilot.press("f")
            await pilot.press("escape")
            await pilot.pause()
            assert app.query_one("#filters", FilterBar).display is False
            assert app._following is False  # the App's escape->follow did NOT fire

            await pilot.press("escape")  # focus is back on the feed: now it follows
            await pilot.pause()
            assert app._following is True
            await app.action_quit()

    async def test_ticking_kinds_rebuilds_the_feed(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(q("example.com"))
            model.add_event(sni("github.com"))
            app._render()
            kinds = app.query_one("#f-kinds", SelectionList)
            kinds.deselect_all()
            kinds.select("dns_query")
            await pilot.pause()
            assert model.filter.kinds == {"dns_query"}
            assert app.query_one("#feed", DataTable).row_count == 1
            await app.action_quit()

    async def test_dimensions_compose_with_and_semantics(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(sni("github.com"))  # dst 1.2.3.4 -> internet
            app._render()
            scopes = app.query_one("#f-scopes", SelectionList)
            scopes.deselect_all()
            scopes.select("lan")  # kind still passes, scope does not
            await pilot.pause()
            assert app.query_one("#feed", DataTable).row_count == 0
            await app.action_quit()

    async def test_filter_emptying_feed_clears_stale_detail(self, tmp_path: Path) -> None:
        # A filter that hides every row must not leave the detail pane showing a now-hidden
        # event, and "nothing matched" must not read as "nothing happened".
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(sni("github.com"))
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            assert "github.com" in str(app.query_one("#detail", Static).render())
            app.query_one("#f-kinds", SelectionList).deselect_all()  # zero kinds = zero rows
            await pilot.pause()
            assert app.query_one("#feed", DataTable).row_count == 0
            detail = str(app.query_one("#detail", Static).render())
            assert "github.com" not in detail
            assert "no rows match the filter" in detail
            await app.action_quit()

    async def test_lists_offer_exactly_the_closed_vocabularies(self, tmp_path: Path) -> None:
        # A drift guard, and the proof that no wire-derived text can enter the filter widget.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            for wid, values in (
                ("#f-kinds", KIND_VALUES),
                ("#f-dirs", DIRECTION_VALUES),
                ("#f-scopes", SCOPE_VALUES),
            ):
                lst = app.query_one(wid, SelectionList)
                assert [s.value for s in lst._options] == list(values)
            await app.action_quit()

    async def test_a_constrained_filter_is_named_in_the_feed_border(self, tmp_path: Path) -> None:
        # A feed that is hiding events must never be mistaken for a quiet network.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            app._render()
            assert "filter" not in str(app.query_one("#feed", DataTable).border_title)
            kinds = app.query_one("#f-kinds", SelectionList)
            kinds.deselect_all()
            kinds.select("dns_query")
            await pilot.pause()
            app._render()
            assert "filter: kind 1/12" in str(app.query_one("#feed", DataTable).border_title)
            await app.action_quit()

    async def test_follow_clears_pause(self, tmp_path: Path) -> None:
        # `g` (follow the newest) resumes the live feed, so it must also un-pause —
        # otherwise the state is paused+following with a lying "PAUSED" panel.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(q("a.com"))
            app._render()
            app.action_toggle_pause()
            assert app.paused is True
            await pilot.press("g")
            assert app.paused is False
            assert app._following is True
            assert app._frozen is None
            await app.action_quit()

    async def test_inspect_mode_is_highlighted(self, tmp_path: Path) -> None:
        # Freezing on a click/nav must be unmissable: the feed box gets the `inspecting`
        # class (colored border) and its title + the health badge say INSPECT. Resuming
        # with `g` clears the highlight and the badge returns to FOLLOW.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 24)) as pilot:
            for i in range(5):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            feed = app.query_one("#feed", DataTable)
            feed.move_cursor(row=2)  # navigate off the top -> INSPECT
            await pilot.pause()
            assert app._following is False
            app._render()  # repaint the mode indicator
            await pilot.pause()
            assert feed.has_class("inspecting")
            assert "INSPECT" in str(feed.border_title)
            assert "INSPECT" in str(app.query_one("#health", Static).render())
            await pilot.press("g")  # follow again
            app._render()
            await pilot.pause()
            assert not feed.has_class("inspecting")
            assert str(feed.border_title) == "live feed"
            assert "FOLLOW" in str(app.query_one("#health", Static).render())
            await app.action_quit()

    async def test_pause_is_highlighted(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(q("a.com"))
            app._render()
            app.action_toggle_pause()
            app._render()
            await pilot.pause()
            feed = app.query_one("#feed", DataTable)
            assert feed.has_class("paused")
            assert "PAUSED" in str(app.query_one("#health", Static).render())
            await app.action_quit()

    async def test_escape_resumes_follow(self, tmp_path: Path) -> None:
        # Esc is a second way out of INSPECT, alongside `g`.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test(size=(100, 24)) as pilot:
            for i in range(5):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            app.query_one("#feed", DataTable).move_cursor(row=2)
            await pilot.pause()
            assert app._following is False
            await pilot.press("escape")
            assert app._following is True
            await app.action_quit()

    async def test_copy_detail_yanks_selected_event(self, tmp_path: Path, monkeypatch) -> None:
        # `y` copies the selected packet's detail text (the same text shown in the pane)
        # through the clipboard helper; a confirmed local copy toasts success.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        copied: list[str] = []
        toasts: list[str] = []

        def fake_copy(text: str, *, env, write) -> netmon_tui.CopyResult:
            copied.append(text)
            return netmon_tui.CopyResult.LOCAL

        async with app.run_test() as pilot:
            monkeypatch.setattr(netmon_tui, "copy_to_clipboard", fake_copy)
            monkeypatch.setattr(app, "notify", lambda msg, **kw: toasts.append(msg))
            event = q("copyme.example.com")
            model.add_event(event)
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            await pilot.press("y")
            assert copied == [event_to_detail(event)]
            assert "copyme.example.com" in copied[0]
            assert toasts == ["copied packet detail to clipboard"]
            await app.action_quit()

    async def test_pause_while_following_then_click_stays_paused_no_inspect_toast(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # Pausing keeps _following True; clicking a row then must NOT pop an INSPECT toast
        # that contradicts the PAUSED border/badge. The toast fires only from FOLLOW.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        toasts: list[str] = []
        async with app.run_test(size=(100, 24)) as pilot:
            monkeypatch.setattr(app, "notify", lambda msg, **kw: toasts.append(msg))
            for i in range(5):
                model.add_event(q(f"h{i}.example.com"))
            app._render()
            await pilot.pause()
            app.action_toggle_pause()  # paused, but still following
            assert app.paused is True
            app.query_one("#feed", DataTable).move_cursor(row=2)  # nav while paused
            await pilot.pause()
            app._render()
            await pilot.pause()
            assert not any("INSPECT" in t for t in toasts)
            feed = app.query_one("#feed", DataTable)
            assert feed.has_class("paused")
            assert not feed.has_class("inspecting")
            assert "PAUSED" in str(app.query_one("#health", Static).render())
            await app.action_quit()

    async def test_copy_detail_without_selection_copies_nothing(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        calls: list[str] = []
        toasts: list[tuple[str, dict]] = []
        async with app.run_test() as pilot:
            monkeypatch.setattr(
                netmon_tui, "copy_to_clipboard", lambda *a, **k: calls.append("called")
            )
            monkeypatch.setattr(app, "notify", lambda msg, **kw: toasts.append((msg, kw)))
            await pilot.press("y")  # nothing selected
            assert calls == []
            assert toasts and "no packet selected" in toasts[0][0]
            assert toasts[0][1].get("severity") == "warning"
            await app.action_quit()

    async def test_copy_detail_terminal_result_reports_best_effort(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # OSC-52-only copies are unconfirmable, so the toast must not claim success.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        toasts: list[str] = []
        async with app.run_test() as pilot:
            monkeypatch.setattr(
                netmon_tui,
                "copy_to_clipboard",
                lambda text, *, env, write: netmon_tui.CopyResult.TERMINAL,
            )
            monkeypatch.setattr(app, "notify", lambda msg, **kw: toasts.append(msg))
            model.add_event(q("x.example.com"))
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            await pilot.press("y")
            assert toasts and "OSC 52" in toasts[0]
            await app.action_quit()

    async def test_copy_detail_failed_result_warns(self, tmp_path: Path, monkeypatch) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        toasts: list[tuple[str, dict]] = []
        async with app.run_test() as pilot:
            monkeypatch.setattr(
                netmon_tui,
                "copy_to_clipboard",
                lambda text, *, env, write: netmon_tui.CopyResult.FAILED,
            )
            monkeypatch.setattr(app, "notify", lambda msg, **kw: toasts.append((msg, kw)))
            model.add_event(q("x.example.com"))
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            await pilot.press("y")
            assert toasts and "copy failed" in toasts[0][0]
            assert toasts[0][1].get("severity") == "warning"
            await app.action_quit()

    async def test_copy_detail_logs_clipboard_event(self, tmp_path: Path, monkeypatch) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            monkeypatch.setattr(
                netmon_tui,
                "copy_to_clipboard",
                lambda text, *, env, write: netmon_tui.CopyResult.LOCAL,
            )
            event = q("logme.example.com")
            model.add_event(event)
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            with capture_logs() as logs:
                await pilot.press("y")
            entries = [e for e in logs if e.get("event") == "clipboard_copy"]
            assert entries and entries[0]["result"] == "local"
            assert entries[0]["chars"] == len(event_to_detail(event))
            await app.action_quit()

    async def test_term_write_emits_via_driver_from_worker_thread(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # The OSC 52 fallback reaches the terminal through the private driver, marshalled
        # back onto the event loop from the clipboard worker thread by call_from_thread.
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        written: list[str] = []
        async with app.run_test():
            monkeypatch.setattr(app._driver, "write", lambda seq: written.append(seq))
            await asyncio.to_thread(app._term_write, "\x1b]52;c;QUJD\a")
            assert written == ["\x1b]52;c;QUJD\a"]
            await app.action_quit()

    async def test_quit_exits_cleanly_and_marks_worker_done(self, tmp_path: Path) -> None:
        # Fix #1: quitting stops capture, the worker completes, and the App exits.
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        async with app.run_test():
            await app.action_quit()
        assert app._worker_done is True
        assert app.return_code == 0
        assert app.worker_exc is None

    async def test_worker_exception_surfaces_as_raise(self, tmp_path: Path, monkeypatch) -> None:
        # Fix #2: a failure in the consume worker (e.g. disk full) must not be
        # swallowed into a clean exit — run_dashboard re-raises it like headless does.
        pkt = (
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.1")
            / UDP(sport=5, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="boom.example", qtype="A"))
        )
        pkt.time = PKT_TIME
        session = make_session(tmp_path, packets=(pkt,))

        def boom(self, event) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(JsonlWriter, "write", boom)
        args = argparse.Namespace(read=None, iface=None, bpf=None, tui=True)
        with pytest.raises(OSError, match="disk full"):
            await run_dashboard(session, args)


# The exact shape that killed the overnight run: a wire-derived string in which a `[`
# opens a markup tag parse and what follows it is not a valid tag. A bare `[` does not
# raise on its own, which is why this survived testing and then fired at 00:23.
HOSTILE = "evil[x=�].example.com"
ANSI = "/a\x1b[2Jb\x00c"


class TestNetmonAppHostileText:
    async def test_hostile_sni_in_detail_pane_does_not_raise(self, tmp_path: Path) -> None:
        # Wire text is data, never markup. The bracket must survive literally, too:
        # escaping it would corrupt the evidence to protect the renderer.
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        async with app.run_test():
            app._set_detail(sni(HOSTILE))
            assert "evil[x=" in str(app.query_one("#detail", Static).render())
            await app.action_quit()

    async def test_hostile_event_at_the_top_of_the_feed_does_not_crash(
        self, tmp_path: Path
    ) -> None:
        # The overnight trigger, with no user interaction: the DataTable auto-highlights
        # row 0 on the follow-mode repaint, which fires on_data_table_row_highlighted.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(sni(HOSTILE))
            app._render()
            await pilot.pause()
            assert app.is_running
            assert "evil[x=" in str(app.query_one("#detail", Static).render())
            await app.action_quit()

    async def test_hostile_hostname_in_hosts_panel_does_not_crash(self, tmp_path: Path) -> None:
        # The same bug, one panel over: remote_hosts keys are DNS/SNI-derived names that
        # never pass through the feed's cell projection.
        session = make_session(tmp_path)
        app = NetmonApp(session, DashboardModel())
        async with app.run_test():
            session.processor.remote_hosts.add(HOSTILE)
            app._render()
            assert "evil[x=" in str(app.query_one("#hosts", Static).render())
            await app.action_quit()

    async def test_control_chars_never_reach_the_feed_cells(self, tmp_path: Path) -> None:
        # Rich and Textual strip only BEL/BS/VT/FF/CR — an ESC in an HTTP path reaches
        # the operator's terminal and drives the cursor. A Text wrapper does not help.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            model.add_event(http_with_path(ANSI))
            app._render()
            row = app.query_one("#feed", DataTable).get_row_at(0)
            assert "\x1b" not in "".join(str(cell) for cell in row)
            assert "\x00" not in "".join(str(cell) for cell in row)
            await app.action_quit()

    async def test_no_panel_parses_markup(self, tmp_path: Path) -> None:
        # The invariant, asserted where it can be violated: every Static this app composes
        # renders what it is given. A panel added later cannot reintroduce the crash.
        app = NetmonApp(make_session(tmp_path), DashboardModel())
        async with app.run_test():
            panels = app.query_one("#feed-col").query(Static).nodes
            panels += app.query_one("#side").query(Static).nodes
            assert panels
            for panel in panels:
                panel.update("[bold]x")
                assert "[bold]x" in str(panel.render())
            await app.action_quit()
