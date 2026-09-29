#!/usr/bin/env python3
"""
LoRa DX-LR30 Meshtastic Monitor

TUI companion for the Flipper Zero LoRa DX-LR30 app. Reads LoRa packets
captured by the Flipper over USB serial, decrypts channel traffic, and
shows messages, nodes, and channels.

Read-only by design: this tool sniffs and decrypts, it does not transmit.

Requirements:
  pip install -r requirements.txt

Usage:
  python3 meshtasticDashboard.py               # interactive device menu
  python3 meshtasticDashboard.py -p /dev/cu.usbmodemflip_...   # skip menu
  python3 meshtasticDashboard.py --list        # list serial devices and exit

Press q to quit.
"""

import argparse
import asyncio
import base64
import json
import queue
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import serial
from serial.tools import list_ports

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from meshtastic import mesh_pb2

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    TabbedContent,
    TabPane,
)

DEFAULT_BAUDRATE = 115200
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
NODES_FILE = REPORTS_DIR / "nodes.json"
KEYS_FILE = REPORTS_DIR / "keys.json"
MESSAGES_FILE = REPORTS_DIR / "messages.jsonl"
CHANNEL_STATS_FILE = REPORTS_DIR / "channel_stats.json"

# Default LongFast channel key (base64 of the standard 16-byte PSK).
DEFAULT_KEYS = ["1PG7OiApB1nwvP+rz05pAQ=="]

BROADCAST_DEST = b"\xff\xff\xff\xff"

# Meshtastic portnums we care about.
PORT_TEXT_MESSAGE = 1
PORT_TELEMETRY = 2
PORT_POSITION = 3
PORT_NODEINFO = 4


def age_str(ts: float) -> str:
    """Compact 'time ago' string for staleness display."""
    if not ts:
        return "-"
    seconds = time.time() - ts
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)}h"
    return f"{int(hours / 24)}d"


def fmt_clock(ts: float) -> str:
    tz = datetime.now().astimezone().tzname() or ""
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") + (f" {tz}" if tz else "")


def fmt_full(ts: float) -> str:
    tz = datetime.now().astimezone().tzname() or ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") + (f" {tz}" if tz else "")


# ---------------------------------------------------------------------------
# Serial helpers
# ---------------------------------------------------------------------------

def classify_port(p) -> str:
    """Return a human label for a serial port based on its USB identity."""
    hwid = (getattr(p, "hwid", None) or "").upper()
    serial_num = (getattr(p, "serial_number", None) or "").lower()
    desc = (getattr(p, "description", None) or "").lower()
    name = (getattr(p, "name", None) or "").lower()

    if "0483" in hwid or "STM" in hwid or "flip" in serial_num or "flipper" in desc:
        return "Flipper Zero (use this)"
    if "1A86" in hwid or "wch" in desc or "ch34" in desc or "ch9102" in desc:
        return "CH34x UART (Meshtastic node / Z-Wave stick)"
    if "303A" in hwid or "espressif" in desc or "esp32" in desc or "jtag" in desc:
        return "ESP32 (Meshtastic node)"
    if "10C4" in hwid or "cp210" in desc:
        return "CP210x UART"
    if "bluetooth" in name or "wlan" in name or "debug" in name or "n/a" in hwid:
        return "system / non-data"
    return "unknown"


def enumerate_ports() -> List:
    ports = [p for p in list_ports.comports() if getattr(p, "device", None)]
    return ports


def interactive_port_selection() -> Optional[str]:
    ports = enumerate_ports()
    if not ports:
        print("No serial devices found. Is the Flipper plugged in?")
        return None

    print("\nSerial devices:")
    for i, p in enumerate(ports, 1):
        print(f"  {i}. {p.device}  [{classify_port(p)}]")
    print("  q. Quit")

    while True:
        choice = input("\nSelect a device number: ").strip().lower()
        if choice == "q":
            return None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(ports):
                return ports[idx].device
        except ValueError:
            pass
        print("Invalid choice, try again.")


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------
#
# Flipper frame: @S | len(2, big) | packet(N) | rssi(2, big, signed) |
#                snr(1, signed) | @E | \r | \n
# Total length = N + 11.

class FrameParser:
    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> List[Tuple[bytes, int, int]]:
        self._buf.extend(chunk)
        frames: List[Tuple[bytes, int, int]] = []

        while True:
            idx = self._buf.find(b"@S")
            if idx < 0:
                if len(self._buf) > 3:
                    del self._buf[:-3]  # keep a tail in case @S is split
                break
            if idx > 0:
                del self._buf[:idx]  # discard CLI noise before @S

            if len(self._buf) < 11:
                break  # need a full header before we know N

            n = int.from_bytes(self._buf[2:4], "big")
            total = n + 11
            if len(self._buf) < total:
                break

            raw = bytes(self._buf[:total])
            if raw.endswith(b"@E\r\n"):
                packet = raw[4:4 + n]
                rssi = int.from_bytes(raw[4 + n:6 + n], "big", signed=True)
                snr = int.from_bytes(raw[6 + n:7 + n], "big", signed=True)
                frames.append((packet, rssi, snr))
                del self._buf[:total]
            else:
                del self._buf[:2]  # corrupted @S, resync

        return frames


def split_packet(packet: bytes) -> Dict[str, bytes]:
    """Split a Meshtastic LoRa frame header. Header is 16 bytes."""
    if len(packet) < 16:
        raise ValueError("packet shorter than 16-byte header")
    return {
        "dest": packet[0:4],
        "sender": packet[4:8],
        "packet_id": packet[8:12],
        "flags": packet[12:13],
        "channel_hash": packet[13:16],
        "payload": packet[16:],
    }


def decrypt_payload(payload: bytes, key_b64: str, sender: bytes, packet_id: bytes) -> bytes:
    """Decrypt a Meshtastic channel payload (AES-CTR, firmware nonce scheme)."""
    key = base64.b64decode(key_b64)
    nonce = packet_id + b"\x00\x00\x00\x00" + sender + b"\x00\x00\x00\x00"
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    return cipher.decryptor().update(payload)


# ---------------------------------------------------------------------------
# Registries (persisted)
# ---------------------------------------------------------------------------

@dataclass
class NodeRecord:
    node_id: str
    long_name: str = ""
    short_name: str = ""
    hw_model: str = ""
    role: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[int] = None
    battery: Optional[int] = None
    node_num: int = 0
    position_time: float = 0.0
    last_seen: float = 0.0
    packets: int = 0

    def display_name(self) -> str:
        # Mirror the Meshtastic app: use the set name, else "Meshtastic XXXX"
        # where XXXX is the last 4 hex chars of the User ID.
        if self.long_name:
            return self.long_name
        return "Meshtastic " + self.node_id[-4:]


class NodeRegistry:
    def __init__(self) -> None:
        self.nodes: Dict[str, NodeRecord] = {}
        self._load()

    def _load(self) -> None:
        if NODES_FILE.exists():
            try:
                raw = json.loads(NODES_FILE.read_text())
                for k, v in raw.items():
                    rec = NodeRecord(**v)
                    if not rec.node_num:
                        rec.node_num = int(k, 16)
                    self.nodes[k] = rec
            except Exception:
                pass

    def save(self) -> None:
        try:
            NODES_FILE.write_text(
                json.dumps({k: asdict(v) for k, v in self.nodes.items()}, indent=2))
        except Exception:
            pass

    def touch(self, sender_hex: str) -> NodeRecord:
        rec = self.nodes.get(sender_hex)
        if rec is None:
            rec = NodeRecord(node_id=sender_hex)
            self.nodes[sender_hex] = rec
        rec.node_num = int(sender_hex, 16)
        rec.packets += 1
        rec.last_seen = time.time()
        return rec

    def resolve(self, sender_hex: str) -> str:
        rec = self.nodes.get(sender_hex)
        return rec.display_name() if rec else ("!" + sender_hex)


class ChannelRegistry:
    def __init__(self) -> None:
        # channel_hash_hex -> {"name": str, "key": str}
        self.channels: Dict[str, Dict[str, str]] = {}
        self._load()
        if not KEYS_FILE.exists():
            self.save()  # create keys.json so the file is present

    def _load(self) -> None:
        if KEYS_FILE.exists():
            try:
                self.channels = json.loads(KEYS_FILE.read_text())
            except Exception:
                pass

    def save(self) -> None:
        try:
            KEYS_FILE.write_text(json.dumps(self.channels, indent=2))
        except Exception:
            pass

    def label(self, channel_hash: bytes) -> str:
        h = channel_hash.hex().upper()
        if h in self.channels:
            return self.channels[h].get("name", "") or ("CH " + h)
        return "CH " + h

    def key_for(self, channel_hash: bytes) -> Optional[str]:
        h = channel_hash.hex().upper()
        ch = self.channels.get(h)
        return ch.get("key") if ch else None


# ---------------------------------------------------------------------------
# Serial reader thread
# ---------------------------------------------------------------------------

class SerialReader:
    def __init__(self, port: str, baudrate: int, frame_queue: queue.Queue) -> None:
        self.port = port
        self.baudrate = baudrate
        self.queue = frame_queue
        self.status = queue.Queue()  # carries (state, message)
        self._running = True
        self._thread: Optional[threading.Thread] = None
        self._ser: Optional[serial.Serial] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._ser and self._ser.is_open:
            try:
                self._ser.close()
            except Exception:
                pass

    def _set_status(self, state: str, msg: str) -> None:
        try:
            self.status.put_nowait((state, msg))
        except Exception:
            pass

    def _open(self) -> bool:
        try:
            if self._ser and self._ser.is_open:
                self._ser.close()
            self._ser = serial.Serial(port=self.port, baudrate=self.baudrate, timeout=0.1)
            return True
        except Exception as e:
            self._set_status("error", f"cannot open {self.port}: {e}")
            return False

    def _run(self) -> None:
        parser = FrameParser()
        while self._running:
            if not (self._ser and self._ser.is_open):
                self._set_status("connecting", f"connecting to {self.port}...")
                if not self._open():
                    time.sleep(2)
                    continue
                self._set_status("connected", f"listening on {self.port}")

            try:
                data = self._ser.read(4096)
                if data:
                    for packet, rssi, snr in parser.feed(data):
                        self.queue.put((packet, rssi, snr))
            except (serial.SerialException, OSError) as e:
                self._set_status("reconnecting", f"serial error ({e}), reconnecting...")
                if self._ser:
                    try:
                        self._ser.close()
                    except Exception:
                        pass
                time.sleep(2)


# ---------------------------------------------------------------------------
# Textual UI
# ---------------------------------------------------------------------------

@dataclass
class MessageRow:
    ts: float
    sender: str
    dest: str
    kind: str
    detail: str
    rssi: int
    size: int

    def cells(self) -> Tuple[str, str, str, str, str, str, str]:
        return (
            fmt_clock(self.ts),
            self.sender,
            self.dest,
            self.kind,
            self.detail,
            str(self.rssi),
            str(self.size),
        )


class LoggingDataTable(DataTable):
    """DataTable that appends each row to a JSONL log file."""

    def __init__(self, log_path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_path = log_path

    def add_row(self, *cells, **kwargs):
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(list(cells), ensure_ascii=False) + "\n")
        except Exception:
            pass
        return super().add_row(*cells, **kwargs)


class AddChannelScreen(ModalScreen):
    """Modal form for adding / editing a channel name and PSK."""

    CSS = """
    #add-channel-dialog {
        width: 74;
        padding: 1 2;
        border: solid $accent;
    }
    #add-channel-dialog > Static {
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_screen", "Cancel"),
        Binding("enter", "submit", "Save"),
    ]

    def __init__(self, default_hash: str = "", default_name: str = "") -> None:
        super().__init__()
        self._default_hash = default_hash
        self._default_name = default_name

    def compose(self) -> ComposeResult:
        with Container(id="add-channel-dialog"):
            yield Static("Add / edit channel", id="title")
            yield Static("Channel hash (6 hex chars):")
            yield Input(placeholder="e.g. 1A2B3C", value=self._default_hash, id="hash-input")
            yield Static("Name (optional):")
            yield Input(placeholder="e.g. CampNet", value=self._default_name, id="name-input")
            yield Static("PSK base64 (optional):")
            yield Input(placeholder="e.g. 1PG7OiApB1nwvP+rz05pAQ==", id="key-input")
            yield Static("[Enter] save   [Esc] cancel", id="hint")

    def on_mount(self) -> None:
        self.call_after_refresh(self.query_one("#hash-input", Input).focus)

    def action_dismiss_screen(self) -> None:
        self.dismiss(None)

    def action_submit(self) -> None:
        h = self.query_one("#hash-input", Input).value.strip().upper()
        name = self.query_one("#name-input", Input).value.strip()
        key = self.query_one("#key-input", Input).value.strip()
        self.dismiss((h, name, key))


class MonitorApp(App):
    CSS = """
    #status { height: 1; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("a", "add_channel", "Add channel"),
    ]

    def __init__(self, reader: SerialReader) -> None:
        super().__init__()
        self.reader = reader
        self.queue = reader.queue
        self.status_queue = reader.status
        self.keys = list(DEFAULT_KEYS)
        self.nodes = NodeRegistry()
        self.channels = ChannelRegistry()
        self.msg_table = LoggingDataTable(MESSAGES_FILE, id="messages")
        self.nodes_table = DataTable(id="nodes")
        self.channels_table = DataTable(id="channels")
        self.channel_msg_table = DataTable(id="channel-messages")
        self.channel_filter_label = Static(
            "Select a channel in the Channels tab to filter messages.", id="channel-filter")
        self.detail = Static("Select a node in the Nodes tab and press Enter.", id="detail")
        self.status = Static("starting...", id="status")
        self.selected_node: Optional[str] = None
        self.selected_channel: Optional[str] = None
        self.message_log: List[Tuple[str, MessageRow]] = []
        self.channel_stats: Dict[str, Dict] = {}
        self._nodes_dirty = True
        self._channels_dirty = True
        self._last_save = time.monotonic()

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Nodes", id="pane-nodes"):
                yield self.nodes_table
            with TabPane("Node Detail", id="pane-detail"):
                yield self.detail
            with TabPane("Channels", id="pane-channels"):
                yield self.channels_table
            with TabPane("Channel Messages", id="pane-channel-messages"):
                with Vertical():
                    yield self.channel_filter_label
                    yield self.channel_msg_table
            with TabPane("Messages", id="pane-messages"):
                yield self.msg_table
        yield self.status
        yield Footer()

    def on_mount(self) -> None:
        self.msg_table.add_columns("Time", "From", "To", "Type", "Detail", "RSSI", "Bytes")
        self.nodes_table.add_columns(
            "User ID", "Node #", "Name", "HW", "Role", "Position", "Pos age", "Batt",
            "Last seen", "Pkts")
        self.nodes_table.cursor_type = "row"
        self.channels_table.add_columns("Channel", "Packets", "Decrypted", "Key?", "Nodes")
        self.channels_table.cursor_type = "row"
        self.channel_msg_table.add_columns(
            "Time", "From", "To", "Type", "Detail", "RSSI", "Bytes")
        self.channel_stats = self._load_channel_stats()
        self.set_interval(0.1, self._pump)

    def _pump(self) -> None:
        while not self.queue.empty():
            packet, rssi, snr = self.queue.get_nowait()
            asyncio.create_task(self._process(packet, rssi, snr))

        while not self.status_queue.empty():
            state, msg = self.status_queue.get_nowait()
            self.status.update(f"[{state}] {msg}")

        # Rebuild the two sortable tables only when their data actually
        # changed. Rebuilding every 0.1s clobbers the cursor/selection, which
        # is why selecting a Node or Channel snapped back to the top.
        if self._nodes_dirty:
            self.nodes_table.clear()
            for rec in sorted(self.nodes.nodes.values(), key=lambda r: -r.last_seen):
                pos = ("%.5f,%.5f" % (rec.latitude, rec.longitude)
                       if rec.latitude is not None and rec.longitude is not None else "-")
                pos_age = age_str(rec.position_time)
                batt = f"{rec.battery}%" if rec.battery is not None else "-"
                self.nodes_table.add_row(
                    "!" + rec.node_id,
                    str(rec.node_num),
                    rec.display_name(),
                    rec.hw_model,
                    rec.role,
                    pos,
                    pos_age,
                    batt,
                    fmt_clock(rec.last_seen) if rec.last_seen else "-",
                    str(rec.packets),
                    key=rec.node_id,
                )
            if self.selected_node is not None:
                try:
                    idx = self.nodes_table.get_row_index(self.selected_node)
                    if idx is not None:
                        self.nodes_table.move_cursor(row=idx, animate=False)
                except Exception:
                    pass
            self._nodes_dirty = False

        if self.selected_node is not None:
            rec = self.nodes.nodes.get(self.selected_node)
            if rec is not None:
                self.detail.update(self._node_detail_text(rec))

        if self._channels_dirty:
            prev_cursor = getattr(self.channels_table, "cursor_row", 0)
            self.channels_table.clear()
            for h, s in self._sorted_channels():
                name = self.channels.channels.get(h, {}).get("name", "") or ("CH " + h)
                senders = ", ".join(
                    self.nodes.resolve(x) for x in sorted(s.get("senders", set())))
                self.channels_table.add_row(
                    name, str(s["packets"]), str(s["decrypted"]),
                    "yes" if self.channels.channels.get(h, {}).get("key") else "-",
                    senders or "-",
                    key=h)
            try:
                nrows = self.channels_table.row_count
                if nrows:
                    self.channels_table.move_cursor(
                        row=min(prev_cursor, nrows - 1), animate=False)
            except Exception:
                pass
            self._channels_dirty = False

        # Persist channel stats periodically so a Ctrl+C / crash loses at
        # most a few seconds, not the whole session.
        now = time.monotonic()
        if now - self._last_save >= 5.0:
            self._save_channel_stats()
            self._last_save = now

    def _node_detail_text(self, rec) -> str:
        lines = [
            f"User ID:  !{rec.node_id}",
            f"Node Num: {rec.node_num}",
            f"Name:     {rec.long_name or '-'} ({rec.short_name or '-'})",
            f"Hardware: {rec.hw_model or '-'}",
            f"Role:     {rec.role or '-'}",
        ]
        if rec.latitude is not None and rec.longitude is not None:
            pos = f"{rec.latitude:.5f}, {rec.longitude:.5f}"
            if rec.altitude is not None:
                pos += f"  alt {rec.altitude} m"
        else:
            pos = "-"
        lines.append(f"Position: {pos}")
        if rec.position_time:
            lines.append(
                "Pos recorded: " + fmt_full(rec.position_time) +
                f" ({age_str(rec.position_time)} ago)")
        else:
            lines.append("Pos recorded: -")
        lines.append(f"Battery:  {f'{rec.battery}%' if rec.battery is not None else '-'}")
        lines.append(f"Packets:  {rec.packets}")
        if rec.last_seen:
            lines.append("Last seen: " + fmt_full(rec.last_seen))
        return "\n".join(lines)

    def on_data_table_row_selected(self, event) -> None:
        table = getattr(event, "data_table", None)
        key = getattr(event, "row_key", None)

        if table is self.nodes_table:
            if key is None:
                return
            rec = self.nodes.nodes.get(key)
            if rec is None:
                return
            self.selected_node = key
            self.detail.update(self._node_detail_text(rec))
            try:
                self.query_one(TabbedContent).active = "pane-detail"
            except Exception:
                pass
        elif table is self.channels_table:
            if key is None:
                return
            self.selected_channel = key
            name = self.channels.channels.get(key, {}).get("name", "") or ("CH " + key)
            self.channel_filter_label.update(f"Filtering channel: {name}  (hash {key})")
            self._rebuild_channel_messages()
            try:
                self.query_one(TabbedContent).active = "pane-channel-messages"
            except Exception:
                pass

    def _load_channel_stats(self) -> Dict[str, Dict]:
        if CHANNEL_STATS_FILE.exists():
            try:
                raw = json.loads(CHANNEL_STATS_FILE.read_text())
                for s in raw.values():
                    s["senders"] = set(s.get("senders", []))
                return raw
            except Exception:
                pass
        return {}

    def _save_channel_stats(self) -> None:
        serializable = {}
        for h, s in self.channel_stats.items():
            serializable[h] = {
                "packets": s.get("packets", 0),
                "decrypted": s.get("decrypted", 0),
                "senders": sorted(s.get("senders", set())),
            }
        try:
            CHANNEL_STATS_FILE.write_text(json.dumps(serializable, indent=2))
        except Exception:
            pass

    def action_quit(self) -> None:
        self._save_channel_stats()
        self.exit()

    def on_unmount(self) -> None:
        self._save_channel_stats()

    def _sorted_channels(self) -> List[Tuple[str, Dict]]:
        return sorted(self.channel_stats.items(), key=lambda kv: -kv[1]["packets"])

    def _add_message(self, chan_hex: str, row: MessageRow) -> None:
        """Add a message to the main table + log, and the filtered view if it
        matches the selected channel."""
        self.message_log.append((chan_hex, row))
        self.msg_table.add_row(*row.cells())
        if self.selected_channel == chan_hex:
            self.channel_msg_table.add_row(*row.cells())

    def _rebuild_channel_messages(self) -> None:
        self.channel_msg_table.clear()
        if self.selected_channel is None:
            return
        for chan_hex, row in self.message_log:
            if chan_hex == self.selected_channel:
                self.channel_msg_table.add_row(*row.cells())

    def _selected_channel_hash(self) -> str:
        items = self._sorted_channels()
        idx = getattr(self.channels_table, "cursor_row", 0)
        if items and 0 <= idx < len(items):
            return items[idx][0]
        return ""

    def action_add_channel(self) -> None:
        asyncio.create_task(self._add_channel())

    async def _add_channel(self) -> None:
        default_hash = self._selected_channel_hash()
        result = await self.push_screen(AddChannelScreen(default_hash=default_hash))
        if not result:
            return
        h, name, key = result
        if len(h) != 6 or not all(c in "0123456789ABCDEF" for c in h):
            self.status.update("[error] Invalid channel hash (need 6 hex chars)")
            return
        self.channels.channels[h] = {"name": name, "key": key}
        self.channels.save()
        self._channels_dirty = True
        self.status.update(f"[ok] Channel {h} saved")

    async def _process(self, packet: bytes, rssi: int, snr: int) -> None:
        try:
            f = split_packet(packet)
        except ValueError:
            return

        sender_hex = f["sender"].hex().upper()
        dest_hex = f["dest"].hex().upper()
        chan_hex = f["channel_hash"].hex().upper()

        self.nodes.touch(sender_hex)
        self._nodes_dirty = True
        st = self.channel_stats.setdefault(
            chan_hex, {"packets": 0, "decrypted": 0, "senders": set()})
        st["packets"] += 1
        st["senders"].add(sender_hex)
        self._channels_dirty = True

        is_broadcast = f["dest"] == BROADCAST_DEST
        dest_label = "broadcast" if is_broadcast else ("!" + dest_hex)

        # Try unencrypted (PSK=none channels), then known keys, then default.
        pb = mesh_pb2.Data()
        handled = self._try_plaintext(pb, f["payload"], sender_hex, rssi, snr, chan_hex)

        if not handled and is_broadcast:
            # Channel key from user registry first, then defaults.
            keys: List[str] = []
            user_key = self.channels.key_for(f["channel_hash"])
            if user_key:
                keys.append(user_key)
            keys += self.keys
            seen = set()
            for k in keys:
                if k in seen:
                    continue
                seen.add(k)
                try:
                    plain = decrypt_payload(
                        f["payload"], k, f["sender"], f["packet_id"])
                except Exception:
                    continue
                if self._try_plaintext(pb, plain, sender_hex, rssi, snr, chan_hex):
                    st["decrypted"] += 1
                    handled = True
                    break

        if not handled:
            if is_broadcast:
                kind = "Channel (enc)"
                detail = f"{len(f['payload'])} bytes, unknown key"
            else:
                kind = "P2P"
                detail = f"DM/ack, {len(f['payload'])} bytes, unreadable"
            self._add_message(chan_hex, MessageRow(
                time.time(), self.nodes.resolve(sender_hex), dest_label,
                kind, detail, rssi, len(f["payload"])))

    def _try_plaintext(
        self, pb: mesh_pb2.Data, payload: bytes, sender_hex: str, rssi: int, snr: int,
        chan_hex: str
    ) -> bool:
        try:
            pb.ParseFromString(payload)
        except Exception:
            pb.Clear()
            return False
        self._handle_data(pb, sender_hex, rssi, snr, chan_hex)
        return True

    def _handle_data(
        self, pb: mesh_pb2.Data, sender_hex: str, rssi: int, snr: int, chan_hex: str
    ) -> None:
        sender = self.nodes.resolve(sender_hex)

        if pb.portnum == PORT_NODEINFO:
            detail = "NodeInfo"
            try:
                user = mesh_pb2.User()
                user.ParseFromString(pb.payload)
                rec = self.nodes.touch(sender_hex)
                rec.long_name = user.long_name
                rec.short_name = user.short_name
                try:
                    rec.hw_model = mesh_pb2.HardwareModel.Name(user.hw_model)
                except Exception:
                    rec.hw_model = str(user.hw_model)
                try:
                    rec.role = mesh_pb2.Config.DeviceRole.Name(user.role)
                except Exception:
                    rec.role = str(user.role)
                self.nodes.save()
                detail = " ".join(x for x in (rec.display_name(), rec.hw_model, rec.role) if x)
            except Exception:
                pass
            self._add_message(chan_hex, MessageRow(
                time.time(), sender, "broadcast", "NodeInfo",
                detail, rssi, len(pb.payload)))
            return

        if pb.portnum == PORT_POSITION:
            detail = "position"
            try:
                pos = mesh_pb2.Position()
                pos.ParseFromString(pb.payload)
                rec = self.nodes.touch(sender_hex)
                rec.latitude = pos.latitude_i / 1e7 if pos.latitude_i else None
                rec.longitude = pos.longitude_i / 1e7 if pos.longitude_i else None
                rec.altitude = pos.altitude if pos.altitude else None
                rec.position_time = time.time()
                self.nodes.save()
                if rec.latitude is not None and rec.longitude is not None:
                    detail = "%.5f,%.5f" % (rec.latitude, rec.longitude)
                    if rec.altitude:
                        detail += " alt=%dm" % rec.altitude
            except Exception:
                pass
            self._add_message(chan_hex, MessageRow(
                time.time(), sender, "broadcast", "Position",
                detail, rssi, len(pb.payload)))
            return

        if pb.portnum == PORT_TELEMETRY:
            detail = "telemetry"
            try:
                tele = mesh_pb2.Telemetry()
                tele.ParseFromString(pb.payload)
                rec = self.nodes.touch(sender_hex)
                which = tele.WhichOneof("variant")
                parts = []
                if which == "device_metrics":
                    dm = tele.device_metrics
                    if dm.battery_level:
                        rec.battery = dm.battery_level
                        parts.append("batt %d%%" % dm.battery_level)
                    if dm.voltage:
                        parts.append("%.2fV" % dm.voltage)
                    if dm.channel_utilization:
                        parts.append("chutil %.1f%%" % dm.channel_utilization)
                    if dm.air_util_tx:
                        parts.append("airtx %.1f%%" % dm.air_util_tx)
                elif which == "environment_metrics":
                    em = tele.environment_metrics
                    if em.temperature:
                        parts.append("%.1f C" % em.temperature)
                    if em.relative_humidity:
                        parts.append("%.0f%% RH" % em.relative_humidity)
                    if em.barometric_pressure:
                        parts.append("%.1f hPa" % em.barometric_pressure)
                elif which == "power_metrics":
                    pm = tele.power_metrics
                    if pm.ch1_voltage:
                        parts.append("ch1 %.2fV" % pm.ch1_voltage)
                    if pm.ch1_current:
                        parts.append("%.0fmA" % pm.ch1_current)
                if parts:
                    self.nodes.save()
                    detail = ", ".join(parts)
            except Exception:
                pass
            self._add_message(chan_hex, MessageRow(
                time.time(), sender, "broadcast", "Telemetry",
                detail, rssi, len(pb.payload)))
            return

        if pb.portnum == PORT_TEXT_MESSAGE:
            try:
                text = pb.payload.decode("utf-8", errors="replace")
            except Exception:
                text = "<error>"
            self._add_message(chan_hex, MessageRow(
                time.time(), sender, "broadcast", "Text", text, rssi, len(pb.payload)))
            return

        self._add_message(chan_hex, MessageRow(
            time.time(), sender, "broadcast", f"Port {pb.portnum}",
            f"{len(pb.payload)} bytes", rssi, len(pb.payload)))


def main() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(description="LoRa DX-LR30 Meshtastic Monitor")
    parser.add_argument("-p", "--port", default=None, help="serial port")
    parser.add_argument("-baud", "--baudrate", type=int, default=DEFAULT_BAUDRATE)
    parser.add_argument("--list", action="store_true", help="list devices and exit")
    parser.add_argument("--no-menu", action="store_true", help="skip device menu")
    args = parser.parse_args()

    if args.list:
        ports = enumerate_ports()
        if not ports:
            print("No serial devices found.")
            return
        for p in ports:
            print(f"{p.device}  [{classify_port(p)}]")
        return

    port = args.port
    if port is None and not args.no_menu:
        port = interactive_port_selection()
    if port is None:
        print("No port selected, exiting.")
        return

    frame_queue: queue.Queue = queue.Queue()
    reader = SerialReader(port, args.baudrate, frame_queue)
    reader.start()
    try:
        MonitorApp(reader).run()
    finally:
        reader.stop()


if __name__ == "__main__":
    main()
