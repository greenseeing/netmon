import argparse
import asyncio
from pathlib import Path

import pytest

pytest.importorskip("textual")

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from textual.widgets import DataTable, Static

from netmon import (
    CaptureStats,
    DashboardModel,
    DnsQueryEvent,
    JsonlWriter,
    PacketProcessor,
    Session,
    TlsSniEvent,
)
from netmon_tui import NetmonApp, run_dashboard

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
            app._render()
            await pilot.pause()
            table = app.query_one("#feed", DataTable)
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
            app.action_cycle_filter()  # -> "dns"; all match, but must use the snapshot
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

    async def test_filter_cycles_and_rebuilds_feed(self, tmp_path: Path) -> None:
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test():
            model.add_event(q("example.com"))
            model.add_event(sni("github.com"))
            app._render()
            app.action_cycle_filter()  # None -> "dns"
            assert model.filter == "dns"
            assert app.query_one("#feed", DataTable).row_count == 1  # only the dns row
            await app.action_quit()

    async def test_filter_emptying_feed_clears_stale_detail(self, tmp_path: Path) -> None:
        # A filter that hides every row must not leave the detail pane showing a
        # now-hidden event.
        model = DashboardModel()
        app = NetmonApp(make_session(tmp_path), model)
        async with app.run_test() as pilot:
            model.add_event(sni("github.com"))
            app._render()
            app.query_one("#feed", DataTable).move_cursor(row=0)
            await pilot.pause()
            assert "github.com" in str(app.query_one("#detail", Static).render())
            app.action_cycle_filter()  # -> "dns": hides the only (tls_sni) row
            await pilot.pause()
            assert app.query_one("#feed", DataTable).row_count == 0
            assert "github.com" not in str(app.query_one("#detail", Static).render())
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
        pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="boom.example", qtype="A")
        )
        pkt.time = PKT_TIME
        session = make_session(tmp_path, packets=(pkt,))

        def boom(self, event) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(JsonlWriter, "write", boom)
        args = argparse.Namespace(read=None, iface=None, bpf=None, tui=True)
        with pytest.raises(OSError, match="disk full"):
            await run_dashboard(session, args)
