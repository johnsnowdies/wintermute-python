import threading
import time
import re
from datetime import datetime
from typing import Optional

from config_manager import ConfigManager, parse_time_interval
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.progress import ProgressBar
from rich.logging import RichHandler
from rich.cells import cell_len
import logging
import sys
import os
try:
    import termios
    import tty
    import select
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

class UI:
    def __init__(self, config_path: str = "config.yaml", config_manager=None):
        self.console = Console()
        self.layout = Layout()

        self.app_logs = []
        self.core_logs = []
        self.max_logs = 100

        self.lock = threading.Lock()
        self.live: Optional[Live] = None

        if config_manager:
            self.config_manager = config_manager
            self.config = config_manager.config
        else:
            self.config_manager = ConfigManager(config_path)
            self.config = self.config_manager.load()

        self._setup_layout()

    def _setup_layout(self):
        self.layout.split(
            Layout(name="header", size=1),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=1),
        )

        self.main_layout = Layout()
        self.main_layout.split_row(
            Layout(name="left", ratio=7),
            Layout(name="status", ratio=3),
        )
        self.main_layout["left"].split(
            Layout(name="app", ratio=1),
            Layout(name="core", ratio=1),
        )

        self.layout["body"].update(self.main_layout)

        self.mode = "TESTING"
        self.profile_name = "None"
        self.health_status = "OK"
        self.health_color = "green"

        self.start_time = datetime.now()
        self.sources = []
        self.last_update = None
        self.test_results = []
        self.core_type = "None"
        self.progress_current = 0
        self.progress_total = 0
        self.show_help = False
        self.hotkeys = {}
        self.broken_profiles = set()
        self.show_manual = False
        self.selected_profile_index = 0
        self.manual_callback = None
        self.show_message_modal = False
        self.modal_title = ""
        self.modal_message = ""

        # Sources Management
        self.show_sources_list = False
        self.selected_source_index = 0
        self.show_source_edit = False
        self.editing_source_index = -1
        self.edit_source_field_index = 0
        self.edit_source_obj = None # Temporary SourceConfig-like dict
        self.source_callback = None # callback(action, index, data)

        # Config Management
        self.show_config_edit = False
        self.selected_config_field_index = 0
        self.config_callback = None # callback() for saving

    def _clean_text(self, text: str) -> str:
        if not text:
            return ""
        # Keep letters, digits, spaces and common punctuation/symbols
        # Pattern includes characters needed for Rich markup and common log output
        pattern = r'[^a-zA-Z0-9а-яА-ЯёЁ\s\-\.\_\(\)\[\]\:\/\,\!\?\+\=\*\&\%\#\@\<\>\;\"\'\^]'
        return re.sub(pattern, '', text)

    def _clean_name(self, name: str) -> str:
        if not name:
            return ""
        cleaned = self._clean_text(name)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.strip()

    def _get_panel(self, logs, title):
        content = Text()
        for log in logs[-20:]: # Show last 20 lines
            content.append(Text.from_markup(log) + "\n")
        return Panel(content, title=title, border_style="blue")

    def _get_footer(self):
        if self.mode == "WORKING":
            mode_bg = "cyan"
        elif self.mode == "HEALTHCHECK":
            mode_bg = "blue"
        else:
            mode_bg = "yellow" # TESTING

        mode_text = Text(f" {self.mode} ", style=f"bold black on {mode_bg}")
        profile_text = Text(f" Profile: {self.profile_name} ", style="bold white")
        health_text = Text(f" Health: {self.health_status} ", style=f"bold black on {self.health_color}")

        # Use Columns or manual construction for alignment
        # rich.layout can't easily do left/center/right in one line without sub-layouts
        # but we can just use a Text object with justified segments if it's 1 line.

        footer_content = Text()
        footer_content.append(mode_text)

        # Calculate padding for center
        console_width = self.console.width
        profile_str = f" Profile: {self.profile_name} "
        health_str = f" Health: {self.health_status} "

        padding_center = (console_width - cell_len(self.mode) - 2 - cell_len(profile_str)) // 2
        if padding_center > 0:
            footer_content.append(" " * padding_center)
        footer_content.append(profile_text)

        padding_right = console_width - cell_len(footer_content.plain) - cell_len(health_str)
        if padding_right > 0:
            footer_content.append(" " * padding_right)
        footer_content.append(health_text)

        return footer_content

    def _get_status_panel(self):
        items = []
        content = Text()

        status_width = int(self.console.width * 0.3) - 4
        if status_width < 20: status_width = 20

        # 0) Progress Bar (if in TESTING mode)
        if self.mode == "TESTING" and self.progress_total > 0:
            content.append("Testing Progress:\n", style="bold green")
            # We add a small offset to account for panel borders and padding
            bar_width = status_width - 2
            if bar_width < 10: bar_width = 10

            bar = ProgressBar(total=self.progress_total, completed=self.progress_current, width=bar_width)

            # Since content is Text, we can't directly append ProgressBar.
            # We will use Group later.
            items.append(content)
            items.append(bar)
            items.append(Text("\n")) # Spacer
            content = Text() # Reset content for next parts

        # 1) Uptime
        uptime = datetime.now() - self.start_time
        uptime_str = str(uptime).split('.')[0]
        content.append("Uptime: ", style="bold yellow")
        content.append(f"{uptime_str}\n")
        content.append("Started: ", style="bold yellow")
        content.append(f"{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # 2) Sources
        if self.sources:
            content.append("Sources:\n", style="bold cyan")
            for src in self.sources:
                content.append(f" {src}\n", style="dim")
            content.append("\n")

        # 2.5) Mode
        if self.mode == "WORKING":
            content.append("Mode: ", style="bold cyan")
            content.append(f"{self.core_type}\n\n")

        # 3) Last Update
        if self.last_update:
            content.append("Updated: ", style="bold cyan")
            lu_dt = datetime.fromtimestamp(self.last_update)
            content.append(f"{lu_dt.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # 4) Test Results
        if self.test_results:
            total_results = len(self.test_results)

            # Calculate available height for test results
            # Usable height is console height minus:
            # - footer (1)
            # - panel borders (2)
            usable_height = self.console.height - 3

            # Lines taken by other sections
            taken_lines = 0
            if self.mode == "TESTING" and self.progress_total > 0:
                taken_lines += 3
            taken_lines += 3 # Uptime
            if self.sources:
                taken_lines += len(self.sources) + 2
            if self.mode == "WORKING":
                taken_lines += 2
            if self.last_update:
                taken_lines += 2
            taken_lines += 1 # Test Results header

            display_count = usable_height - taken_lines

            # If we need to show "and X more", it takes one more line
            if total_results > display_count and display_count > 0:
                display_count -= 1

            if display_count < 1:
                display_count = 1 # Show at least one if possible

            content.append(f"Test Results ({total_results}):\n", style="bold magenta")
            # Show top results
            for p in self.test_results[:display_count]:
                raw_name = p.comment or p.host
                is_current = self._clean_name(raw_name) == self.profile_name
                is_broken = p.raw_url in self.broken_profiles

                if p.comment:
                    name = self._clean_name(f"{p.comment} ({p.host})")
                else:
                    name = self._clean_name(p.host)

                ping = p.latency
                if ping is None:
                    ping_str = "TIMEOUT"
                    ping_style = "red"
                elif ping < self.config.selection.min_acceptable_latency:
                    ping_str = f"{ping}ms"
                    ping_style = "green"
                elif ping < self.config.selection.min_acceptable_latency + self.config.selection.min_acceptable_latency / 2:
                    ping_str = f"{ping}ms"
                    ping_style = "yellow"
                else:
                    ping_str = f"{ping}ms"
                    ping_style = "red"

                if is_broken:
                    ping_style = "dim gray"

                prefix = "> " if is_current else "  "
                protocol_char = "X" if p.extra.get("type") == "xhttp" else "S"

                if is_broken:
                    protocol_style = "dim gray"
                    name_style = "dim gray"
                else:
                    protocol_style = "bold green" if protocol_char == "X" else "bold orange1"
                    name_style = "bold white" if is_current else ""

                # Calculate space for name
                # available = status_width - cell_len(prefix) - 2 (prot + space) - cell_len(ping_str) - 1 (min space)
                max_name_len = status_width - cell_len(prefix) - 2 - cell_len(ping_str) - 1
                if cell_len(name) > max_name_len:
                    # Text.truncate uses cell length
                    t_name = Text(name)
                    t_name.truncate(max_name_len - 3)
                    name = t_name.plain + "..."

                # Padding to right-align ping
                padding_len = status_width - cell_len(prefix) - 2 - cell_len(name) - cell_len(ping_str)
                if padding_len < 1: padding_len = 1
                padding = " " * padding_len

                line = Text()
                line.append(prefix, style="bold blink" if is_current else "")
                line.append(protocol_char, style=protocol_style)
                line.append(" ")
                line.append(name, style=name_style)
                line.append(padding)
                line.append(ping_str, style=ping_style)
                content.append(line)
                content.append("\n")

            if total_results > display_count:
                content.append(f"  ... and {total_results - display_count} more\n", style="dim")

        items.append(content)
        return Panel(Group(*items), title="Status", border_style="green")

    def update_render(self):
        with self.lock:
            self.layout["header"].update(self._get_header())
            self.layout["footer"].update(self._get_footer())

            if self.show_help:
                self.layout["body"].update(self._get_help_panel())
            elif self.show_manual:
                self.layout["body"].update(self._get_manual_panel())
            elif self.show_message_modal:
                self.layout["body"].update(self._get_message_panel())
            elif self.show_sources_list:
                self.layout["body"].update(self._get_sources_list_panel())
            elif self.show_source_edit:
                self.layout["body"].update(self._get_source_edit_panel())
            elif self.show_config_edit:
                self.layout["body"].update(self._get_config_edit_panel())
            else:
                self.layout["body"].update(self.main_layout)
                self.main_layout["left"]["app"].update(self._get_panel(self.app_logs, "Application Logs"))
                self.main_layout["left"]["core"].update(self._get_panel(self.core_logs, "Core (Sing-box/Xray) Logs"))
                self.main_layout["status"].update(self._get_status_panel())

    def set_status_data(self, sources=None, last_update=None, test_results=None, broken_profiles=None):
        with self.lock:
            if sources is not None:
                self.sources = [self._clean_name(s) for s in sources]
                # Ensure selected source index is within bounds
                total_sources = len(self.config.sources)
                if self.selected_source_index >= total_sources:
                    self.selected_source_index = max(0, total_sources - 1)
            if last_update is not None:
                self.last_update = last_update
            if test_results is not None:
                self.test_results = test_results
            if broken_profiles is not None:
                self.broken_profiles = broken_profiles
        if self.live:
            self.update_render()

    def set_mode(self, mode: str):
        with self.lock:
            if self.mode != mode:
                # Reset uptime when entering TESTING or WORKING mode
                # But don't reset when returning from HEALTHCHECK to WORKING
                if mode in ["TESTING", "WORKING"]:
                    if not (self.mode == "HEALTHCHECK" and mode == "WORKING"):
                        self.start_time = datetime.now()
                self.mode = mode
        if self.live:
            self.update_render()

    def set_profile(self, name: str):
        with self.lock:
            self.profile_name = self._clean_name(name)
        if self.live:
            self.update_render()

    def set_health(self, status: str, color: str):
        with self.lock:
            self.health_status = status
            self.health_color = color
        if self.live:
            self.update_render()

    def set_core_type(self, core_type: str):
        with self.lock:
            self.core_type = core_type
        if self.live:
            self.update_render()

    def set_progress(self, current: int, total: int):
        with self.lock:
            self.progress_current = current
            self.progress_total = total
        if self.live:
            self.update_render()

    def add_app_log(self, message: str):
        # Calculate available width (70% for left panel minus borders/padding)
        width = int(self.console.width * 0.7) - 4
        if width < 10: width = 10

        with self.lock:
            # Handle multiple lines if present
            lines = message.splitlines()
            truncated_lines = []
            for line in lines:
                line = self._clean_text(line)
                try:
                    t = Text.from_markup(line)
                    if t.cell_len > width:
                        t.truncate(width - 3)
                        t.append("...")
                        truncated_lines.append(t.markup)
                    else:
                        truncated_lines.append(line)
                except Exception:
                    # Fallback for invalid markup
                    if cell_len(line) > width:
                        t = Text(line)
                        t.truncate(width - 3)
                        truncated_lines.append(t.plain + "...")
                    else:
                        truncated_lines.append(line)

            message = "\n".join(truncated_lines)
            self.app_logs.append(message)
            if len(self.app_logs) > self.max_logs:
                self.app_logs.pop(0)
        if self.live:
            self.update_render()

    def add_core_log(self, message: str):
        # Calculate available width (70% for left panel minus borders/padding)
        width = int(self.console.width * 0.7) - 4
        if width < 10: width = 10

        with self.lock:
            # Handle multiple lines if present
            lines = message.splitlines()
            truncated_lines = []
            for line in lines:
                line = self._clean_text(line)
                try:
                    t = Text.from_markup(line)
                    if t.cell_len > width:
                        t.truncate(width - 3)
                        t.append("...")
                        truncated_lines.append(t.markup)
                    else:
                        truncated_lines.append(line)
                except Exception:
                    # Fallback for invalid markup
                    if cell_len(line) > width:
                        t = Text(line)
                        t.truncate(width - 3)
                        truncated_lines.append(t.plain + "...")
                    else:
                        truncated_lines.append(line)

            message = "\n".join(truncated_lines)
            self.core_logs.append(message)
            if len(self.core_logs) > self.max_logs:
                self.core_logs.pop(0)
        if self.live:
            self.update_render()

    def _get_header(self):
        header = Text()
        header.append(" [F1]", style="bold cyan")
        header.append(" Help  ", style="white")
        header.append("[F2]", style="bold cyan")
        header.append(" Manual  ", style="white")
        header.append("[F3]", style="bold cyan")
        header.append(" Sources  ", style="white")
        header.append("[F4]", style="bold cyan")
        header.append(" Config  ", style="white")
        header.append("[F5]", style="bold cyan")
        header.append(" Reload  ", style="white")
        header.append("[F6]", style="bold cyan")
        header.append(" Switch  ", style="white")
        header.append("[F7]", style="bold cyan")
        header.append(" Retest  ", style="white")
        header.append("[F8]", style="bold cyan")
        header.append(" USB", style="white")
        return header

    def _get_help_panel(self):
        help_text = Text()
        help_text.append("\n Wintermute Hotkeys\n\n", style="bold yellow")
        help_text.append(" [F1] ", style="bold cyan")
        help_text.append("- Toggle this help screen\n")
        help_text.append(" [F2] ", style="bold cyan")
        help_text.append("- Manual profile selection\n")
        help_text.append(" [F3] ", style="bold cyan")
        help_text.append("- Manage profile sources\n")
        help_text.append(" [F4] ", style="bold cyan")
        help_text.append("- Edit application configuration\n")
        help_text.append(" [F5] ", style="bold cyan")
        help_text.append("- Reload profiles from sources (URLs)\n")
        help_text.append(" [F6] ", style="bold cyan")
        help_text.append("- Switch to the next best profile (current marked as broken)\n")
        help_text.append(" [F7] ", style="bold cyan")
        help_text.append("- Clear broken profiles and start full re-test\n")
        help_text.append(" [F8] ", style="bold cyan")
        help_text.append("- Load profiles from USB drive (profile_*.json)\n\n")
        help_text.append(" [Arrows] ", style="bold cyan")
        help_text.append("- Navigate in manual selection mode\n")
        help_text.append(" [Enter] ", style="bold cyan")
        help_text.append("- Select profile or refresh UI\n\n")
        help_text.append(" [Ctrl+C] ", style="bold red")
        help_text.append("- Terminate application\n\n")
        help_text.append(" More features coming soon...", style="italic dim")

        return Panel(help_text, title="Help", border_style="cyan")

    def toggle_help(self):
        with self.lock:
            self.show_help = not self.show_help
            if self.show_help:
                self.show_manual = False
                self.show_message_modal = False
        if self.live:
            self.update_render()

    def show_message(self, title: str, message: str):
        with self.lock:
            self.modal_title = title
            self.modal_message = message
            self.show_message_modal = True
            self.show_help = False
            self.show_manual = False
        if self.live:
            self.update_render()

    def _get_message_panel(self):
        content = Text()
        content.append(f"\n {self.modal_message}\n\n", style="bold white")
        content.append(" Press Enter to close", style="dim")
        return Panel(
            Align.center(content, vertical="middle"),
            title=self.modal_title,
            border_style="bold yellow"
        )

    def _get_sources_list_panel(self):
        content = Text()
        sources = self.config.sources
        total = len(sources)

        if not sources:
            content.append("\n  No sources found.\n\n", style="bold red")
        else:
            # Scroll logic
            panel_height = self.console.height - 10
            if panel_height < 5: panel_height = 5

            start_idx = max(0, self.selected_source_index - panel_height // 2)
            end_idx = min(total, start_idx + panel_height)
            if end_idx - start_idx < panel_height:
                start_idx = max(0, end_idx - panel_height)

            if start_idx > 0:
                content.append("  ↑ ... more sources above\n", style="dim")

            for i in range(start_idx, end_idx):
                src = sources[i]
                is_selected = (i == self.selected_source_index)
                style = "bold white on blue" if is_selected else ("white" if src.enabled else "dim gray")

                status_char = "[+]" if src.enabled else "[ ]"
                line = Text()
                line.append(f" {status_char} ", style=style)
                line.append(f"{src.url} ", style=style)

                # Metadata
                meta = f"({src.type}, {src.refresh}s)"
                padding = self.console.width - cell_len(line.plain) - cell_len(meta) - 6
                if padding > 0:
                    line.append(" " * padding, style=style)
                line.append(meta, style=style)

                content.append(line)
                content.append("\n")

            if end_idx < total:
                content.append("  ↓ ... more sources below\n", style="dim")

        footer = Text("\n [a] Add  [d] Delete  [Enter] Edit  [F3/Esc] Close", justify="center", style="bold cyan")

        return Panel(
            Group(content, footer),
            title="Profile Sources",
            border_style="cyan",
            padding=(1, 1)
        )

    def _get_source_edit_panel(self):
        if not self.edit_source_obj:
            return Panel(Text("Error: No source to edit"), title="Error")

        content = Text()
        fields = [
            ("URL", self.edit_source_obj["url"]),
            ("Refresh", str(self.edit_source_obj["refresh"])),
            ("Filter", self.edit_source_obj["filter"]),
            ("Enabled", "Yes" if self.edit_source_obj["enabled"] else "No"),
        ]

        content.append("\n Editing Source\n\n", style="bold yellow")

        for i, (label, value) in enumerate(fields):
            is_selected = (i == self.edit_source_field_index)
            style = "bold white on blue" if is_selected else "white"

            line = Text()
            line.append(f" {label:10}: ", style="bold cyan")
            line.append(f" {value} ", style=style)
            content.append(line)
            content.append("\n")

        content.append("\n [Enter] Change Value  [s] Save  [Esc] Cancel", style="bold cyan")

        return Panel(
            Align.center(content, vertical="middle"),
            title="Source Editor",
            border_style="bold green",
            padding=(1, 2)
        )

    def toggle_sources(self, callback=None):
        with self.lock:
            self.show_sources_list = not self.show_sources_list
            if self.show_sources_list:
                self.show_help = False
                self.show_manual = False
                self.show_message_modal = False
                self.source_callback = callback
                self.selected_source_index = 0
        if self.live:
            self.update_render()

    def toggle_source_edit(self, source_index=None):
        with self.lock:
            if source_index is not None and 0 <= source_index < len(self.config.sources):
                src = self.config.sources[source_index]
                self.editing_source_index = source_index
                self.edit_source_obj = {
                    "url": src.url,
                    "type": src.type,
                    "refresh": src.refresh,
                    "filter": src.filter,
                    "enabled": src.enabled,
                    "priority": src.priority
                }
                self.show_source_edit = True
                self.show_sources_list = False
                self.edit_source_field_index = 0
            elif source_index == -1: # New source
                self.editing_source_index = -1
                self.edit_source_obj = {
                    "url": "https://",
                    "type": "base64",
                    "refresh": 3600,
                    "filter": "",
                    "enabled": True,
                    "priority": 1
                }
                self.show_source_edit = True
                self.show_sources_list = False
                self.edit_source_field_index = 0
            else:
                self.show_source_edit = False
                self.show_sources_list = True
                self.edit_source_obj = None
        if self.live:
            self.update_render()

    def _get_config_edit_panel(self):
        fields = self._get_config_fields()
        content = Text()

        # Scroll logic
        panel_height = self.console.height - 10
        if panel_height < 5: panel_height = 5

        total = len(fields)
        start_idx = max(0, self.selected_config_field_index - panel_height // 2)
        end_idx = min(total, start_idx + panel_height)
        if end_idx - start_idx < panel_height:
            start_idx = max(0, end_idx - panel_height)

        if start_idx > 0:
            content.append("  ↑ ... more settings above\n", style="dim")

        for i in range(start_idx, end_idx):
            f = fields[i]
            is_selected = (i == self.selected_config_field_index)
            style = "bold white on blue" if is_selected else "white"

            line = Text()
            line.append(f" {f['label']:30}: ", style="bold cyan")

            val_display = str(f['val'])
            if f['type'] == bool:
                val_display = "Yes" if f['val'] else "No"

            line.append(f" {val_display} ", style=style)
            content.append(line)
            content.append("\n")

        if end_idx < total:
            content.append("  ↓ ... more settings below\n", style="dim")

        footer = Text("\n [Enter] Change Value  [s] Save & Close  [Esc] Cancel", justify="center", style="bold cyan")

        return Panel(
            Group(content, footer),
            title="Application Configuration",
            border_style="bold green",
            padding=(1, 2)
        )

    def _get_config_fields(self):
        c = self.config

        def to_interval(sec):
            if sec % 3600 == 0: return f"{sec // 3600}h"
            if sec % 60 == 0: return f"{sec // 60}m"
            return f"{sec}s"

        return [
            {"label": "Cache: Enabled", "val": c.cache.enabled, "type": bool, "obj": c.cache, "attr": "enabled"},
            {"label": "Cache: Directory", "val": c.cache.directory, "type": str, "obj": c.cache, "attr": "directory"},
            {"label": "Cache: Fallback on Error", "val": c.cache.fallback_on_error, "type": bool, "obj": c.cache, "attr": "fallback_on_error"},

            {"label": "Network: Interface", "val": c.network.interface, "type": str, "obj": c.network, "attr": "interface"},
            {"label": "Network: Exclude Subnets", "val": ", ".join(c.network.exclude_subnets), "type": list, "obj": c.network, "attr": "exclude_subnets"},
            {"label": "Network: TUN Name", "val": c.network.tun_name, "type": str, "obj": c.network, "attr": "tun_name"},
            {"label": "Network: TUN Subnet", "val": c.network.tun_subnet, "type": str, "obj": c.network, "attr": "tun_subnet"},
            {"label": "Network: MTU", "val": c.network.mtu, "type": int, "obj": c.network, "attr": "mtu"},
            {"label": "Network: IPv4 Forward", "val": c.network.ipv4_forward, "type": bool, "obj": c.network, "attr": "ipv4_forward"},

            {"label": "Testing: Healthcheck URLs", "val": ", ".join(c.testing.healthcheck_urls), "type": list, "obj": c.testing, "attr": "healthcheck_urls"},
            {"label": "Testing: Content URL", "val": c.testing.healthcheck_content_url or "", "type": str, "obj": c.testing, "attr": "healthcheck_content_url"},
            {"label": "Testing: Content MD5", "val": c.testing.healthcheck_content_md5 or "", "type": str, "obj": c.testing, "attr": "healthcheck_content_md5"},
            {"label": "Testing: Timeout", "val": c.testing.timeout, "type": int, "obj": c.testing, "attr": "timeout"},
            {"label": "Testing: Health Interval", "val": to_interval(c.testing.healthcheck_interval), "type": "interval", "obj": c.testing, "attr": "healthcheck_interval"},
            {"label": "Testing: Failure Threshold", "val": c.testing.failure_threshold, "type": int, "obj": c.testing, "attr": "failure_threshold"},
            {"label": "Testing: Initial Delay", "val": to_interval(c.testing.initial_delay), "type": "interval", "obj": c.testing, "attr": "initial_delay"},
            {"label": "Testing: Max Test", "val": c.testing.max_test, "type": int, "obj": c.testing, "attr": "max_test"},

            {"label": "Selection: Strategy", "val": c.selection.strategy, "type": str, "obj": c.selection, "attr": "strategy"},
            {"label": "Selection: Min Latency", "val": c.selection.min_acceptable_latency, "type": int, "obj": c.selection, "attr": "min_acceptable_latency"},
            {"label": "Selection: Auto Switch", "val": c.selection.auto_switch, "type": bool, "obj": c.selection, "attr": "auto_switch"},
            {"label": "Selection: Switch Delay", "val": to_interval(c.selection.switch_delay), "type": "interval", "obj": c.selection, "attr": "switch_delay"},
            {"label": "Selection: Backup Count", "val": c.selection.backup_profiles_count, "type": int, "obj": c.selection, "attr": "backup_profiles_count"},
            {"label": "Selection: Prefer Xray", "val": c.selection.prefer_xray, "type": bool, "obj": c.selection, "attr": "prefer_xray"},
        ]

    def toggle_config_edit(self, callback=None):
        with self.lock:
            self.show_config_edit = not self.show_config_edit
            if self.show_config_edit:
                self.show_help = False
                self.show_manual = False
                self.show_message_modal = False
                self.show_sources_list = False
                self.show_source_edit = False
                self.config_callback = callback
                self.selected_config_field_index = 0
        if self.live:
            self.update_render()

    def _get_input_modal(self, prompt, default_value=""):
        # This needs a special way to get input without breaking Live.
        # We'll use a simple approach: stop live, ask input, start live.
        if not self.live:
            return input(f"{prompt} [{default_value}]: ") or default_value

        self.live.stop()
        try:
            # Re-enable echo and canonical mode for input
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                val = input(f"\n{prompt} [{default_value}]: ") or default_value
            finally:
                tty.setcbreak(fd)
            return val
        finally:
            self.live.start()

    def toggle_manual(self, callback=None):
        with self.lock:
            if not self.test_results:
                return
            self.show_manual = not self.show_manual
            if self.show_manual:
                self.show_help = False
                self.show_message_modal = False
                self.manual_callback = callback
                # Set initial selection to current profile if found
                self.selected_profile_index = 0
                for i, p in enumerate(self.test_results):
                    raw_name = p.comment or p.host
                    if self._clean_name(raw_name) == self.profile_name:
                        self.selected_profile_index = i
                        break
        if self.live:
            self.update_render()

    def _get_manual_panel(self):
        content = Text()
        content.append("\n Manual Profile Selection\n\n", style="bold yellow")

        if not self.test_results:
            content.append(" No results available.", style="italic dim")
            return Panel(content, title="Manual Selection", border_style="cyan")

        # Usable height for the list
        # Header (1) + Help title (1) + padding (3) + footer (1) + borders (2)
        usable_height = self.console.height - 8
        if usable_height < 5: usable_height = 5

        total = len(self.test_results)

        # Calculate scroll window
        start_idx = 0
        if self.selected_profile_index >= usable_height // 2:
            start_idx = self.selected_profile_index - usable_height // 2

        if start_idx + usable_height > total:
            start_idx = max(0, total - usable_height)

        end_idx = min(total, start_idx + usable_height)

        if start_idx > 0:
            content.append("  ↑ ... more profiles above\n", style="dim")

        for i in range(start_idx, end_idx):
            p = self.test_results[i]
            is_selected = (i == self.selected_profile_index)
            is_broken = p.raw_url in self.broken_profiles

            # Reusing status panel formatting logic
            raw_name = p.comment or p.host
            is_current = self._clean_name(raw_name) == self.profile_name

            if p.comment:
                name = self._clean_name(f"{p.comment} ({p.host})")
            else:
                name = self._clean_name(p.host)

            ping = p.latency
            if ping is None:
                ping_str = "TIMEOUT"
                ping_style = "red"
            elif ping < self.config.selection.min_acceptable_latency:
                ping_str = f"{ping}ms"
                ping_style = "green"
            elif ping < self.config.selection.min_acceptable_latency + self.config.selection.min_acceptable_latency / 2:
                ping_str = f"{ping}ms"
                ping_style = "yellow"
            else:
                ping_str = f"{ping}ms"
                ping_style = "red"

            if is_broken:
                ping_style = "dim gray"

            protocol_char = "X" if p.extra.get('type') == 'xhttp' else "S"
            protocol_style = "bold green" if p.extra.get('type') == 'xhttp' else "bold orange3"

            if is_selected:
                style = "bold white on blue"
                prefix = "> "
            else:
                style = "dim gray" if is_broken else "white"
                prefix = "  "

            line = Text()
            line.append(prefix, style="bold blink" if (is_current and not is_selected) else "")
            line.append(protocol_char, style=protocol_style if not is_selected else "bold white on blue")
            line.append(" ")
            line.append(name, style=style)

            # Alignment
            # Panel is centered or full width? _get_manual_panel is used in body
            # body width is full console width
            panel_width = self.console.width - 4
            current_len = cell_len(prefix) + cell_len(protocol_char) + 1 + cell_len(name)
            padding_len = panel_width - current_len - cell_len(ping_str) - 2
            if padding_len > 0:
                line.append(" " * padding_len)

            line.append(ping_str, style=ping_style if not is_selected else "bold white on blue")

            content.append(line)
            content.append("\n")

        if end_idx < total:
            content.append("  ↓ ... more profiles below\n", style="dim")

        return Panel(content, title="Manual Selection", border_style="cyan")

    def register_hotkey(self, key: str, callback):
        self.hotkeys[key] = callback

    def _handle_hotkey(self, key: str):
        if key == "F1":
            self.toggle_help()
        elif key in self.hotkeys:
            callback = self.hotkeys[key]
            if callback:
                def safe_callback():
                    try:
                        callback()
                    except Exception as e:
                        logging.error(f"Error in hotkey {key} callback: {e}")
                # Run callback in a separate thread to not block input loop
                threading.Thread(target=safe_callback, daemon=True).start()

    def _input_task(self):
        if not HAS_TERMIOS:
            return

        fd = sys.stdin.fileno()
        try:
            old_settings = termios.tcgetattr(fd)
        except Exception:
            return # Not a TTY

        try:
            tty.setcbreak(fd)
            while not self._stop_event.is_set():
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        # Read all available bytes
                        data = os.read(fd, 1024).decode('utf-8', errors='ignore')
                    except Exception:
                        continue

                    if not data:
                        continue

                    # F1 sequences
                    if any(f1 in data for f1 in ['\x1bOP', '\x1b[11~', '\x1b[[A', '\x1bO1P', '\x1b[P']):
                        self._handle_hotkey("F1")
                    # F2 sequences
                    elif any(f2 in data for f2 in ['\x1bOQ', '\x1b[12~', '\x1b[[B', '\x1bO1Q', '\x1b[Q']):
                        self._handle_hotkey("F2")
                    # F3 sequences
                    elif any(f3 in data for f3 in ['\x1bOR', '\x1b[13~', '\x1b[[C', '\x1bO1R', '\x1b[R']):
                        self._handle_hotkey("F3")
                    # F4 sequences
                    elif any(f4 in data for f4 in ['\x1bOS', '\x1b[14~', '\x1b[[D', '\x1bO1S', '\x1b[S']):
                        self._handle_hotkey("F4")
                    # F5 sequences
                    elif any(f5 in data for f5 in ['\x1b[15~', '\x1bOT', '\x1b[15;2~', '\x1b[15;5~']):
                        self._handle_hotkey("F5")
                    # F6 sequences
                    elif any(f6 in data for f6 in ['\x1b[17~', '\x1bOU', '\x1b[17;2~', '\x1b[17;5~']):
                        self._handle_hotkey("F6")
                    # F7 sequences
                    elif any(f7 in data for f7 in ['\x1b[18~', '\x1bOV', '\x1b[18;2~', '\x1b[18;5~']):
                        self._handle_hotkey("F7")
                    # F8 sequences
                    elif any(f8 in data for f8 in ['\x1b[19~', '\x1bOW', '\x1b[19;2~', '\x1b[19;5~']):
                        self._handle_hotkey("F8")
                    # Navigation and selection
                    elif self.show_manual:
                        if any(up in data for up in ['\x1b[A', 'k']): # Up or 'k'
                            with self.lock:
                                self.selected_profile_index = max(0, self.selected_profile_index - 1)
                            self.update_render()
                        elif any(down in data for down in ['\x1b[B', 'j']): # Down or 'j'
                            with self.lock:
                                self.selected_profile_index = min(len(self.test_results) - 1, self.selected_profile_index + 1)
                            self.update_render()
                        elif '\n' in data or '\r' in data:
                            # Selection confirmed
                            profile = None
                            callback = None
                            with self.lock:
                                if 0 <= self.selected_profile_index < len(self.test_results):
                                    profile = self.test_results[self.selected_profile_index]
                                    callback = self.manual_callback
                                self.show_manual = False

                            if callback and profile:
                                threading.Thread(target=callback, args=(profile,), daemon=True).start()

                            if self.live:
                                self.update_render()
                    # Close message modal
                    elif self.show_message_modal:
                        if '\n' in data or '\r' in data:
                            with self.lock:
                                self.show_message_modal = False
                            if self.live:
                                self.update_render()
                    # Config Edit navigation
                    elif self.show_config_edit:
                        fields = self._get_config_fields()
                        if any(up in data for up in ['\x1b[A', 'k']):
                            with self.lock:
                                self.selected_config_field_index = max(0, self.selected_config_field_index - 1)
                            self.update_render()
                        elif any(down in data for down in ['\x1b[B', 'j']):
                            with self.lock:
                                self.selected_config_field_index = min(len(fields) - 1, self.selected_config_field_index + 1)
                            self.update_render()
                        elif '\x1b' in data and len(data) == 1: # Escape
                            self.toggle_config_edit()
                        elif 's' in data:
                            callback = self.config_callback
                            if callback:
                                threading.Thread(target=callback, daemon=True).start()
                            self.toggle_config_edit()
                        elif '\n' in data or '\r' in data:
                            # Change value
                            field = fields[self.selected_config_field_index]
                            obj = field['obj']
                            attr = field['attr']
                            ftype = field['type']

                            if ftype == bool:
                                setattr(obj, attr, not getattr(obj, attr))
                            else:
                                current_val = str(field['val'])
                                new_val = self._get_input_modal(field['label'], current_val)
                                try:
                                    if ftype == int:
                                        setattr(obj, attr, int(new_val))
                                    elif ftype == list:
                                        setattr(obj, attr, [s.strip() for s in new_val.split(",") if s.strip()])
                                    elif ftype == "interval":
                                        setattr(obj, attr, parse_time_interval(new_val))
                                    else:
                                        setattr(obj, attr, new_val)
                                except Exception as e:
                                    logging.error(f"Error setting config field: {e}")
                                    self.show_message("Error", str(e))
                            self.update_render()
                    # Sources List navigation
                    elif self.show_sources_list:
                        if any(up in data for up in ['\x1b[A', 'k']):
                            with self.lock:
                                self.selected_source_index = max(0, self.selected_source_index - 1)
                            self.update_render()
                        elif any(down in data for down in ['\x1b[B', 'j']):
                            with self.lock:
                                self.selected_source_index = min(len(self.config.sources) - 1, self.selected_source_index + 1)
                            self.update_render()
                        elif '\x1b' in data and len(data) == 1: # Escape
                            self.toggle_sources()
                        elif 'd' in data:
                            callback = self.source_callback
                            idx = self.selected_source_index
                            if callback:
                                threading.Thread(target=callback, args=("delete", idx, None), daemon=True).start()
                        elif 'a' in data:
                            self.toggle_source_edit(source_index=-1)
                        elif '\n' in data or '\r' in data:
                            self.toggle_source_edit(source_index=self.selected_source_index)
                    # Source Edit navigation
                    elif self.show_source_edit:
                        if any(up in data for up in ['\x1b[A', 'k']):
                            with self.lock:
                                self.edit_source_field_index = max(0, self.edit_source_field_index - 1)
                            self.update_render()
                        elif any(down in data for down in ['\x1b[B', 'j']):
                            with self.lock:
                                self.edit_source_field_index = min(3, self.edit_source_field_index + 1)
                            self.update_render()
                        elif '\x1b' in data and len(data) == 1: # Escape
                            self.toggle_source_edit()
                        elif 's' in data:
                            callback = self.source_callback
                            idx = self.editing_source_index
                            if callback:
                                threading.Thread(target=callback, args=("save", idx, self.edit_source_obj), daemon=True).start()
                            self.toggle_source_edit()
                        elif '\n' in data or '\r' in data:
                            # Prompt for value
                            field_idx = self.edit_source_field_index
                            fields = ["url", "refresh", "filter", "enabled"]
                            field_name = fields[field_idx]
                            current_val = self.edit_source_obj[field_name]

                            if field_name == "enabled":
                                with self.lock:
                                    self.edit_source_obj["enabled"] = not self.edit_source_obj["enabled"]
                                self.update_render()
                            else:
                                new_val = self._get_input_modal(f"Enter {field_name}", str(current_val))
                                with self.lock:
                                    if field_name == "refresh":
                                        try:
                                            # Try to parse as interval if it ends with h/m/s
                                            from config_manager import parse_time_interval
                                            self.edit_source_obj["refresh"] = parse_time_interval(new_val)
                                        except:
                                            try: self.edit_source_obj["refresh"] = int(new_val)
                                            except: pass
                                    else:
                                        self.edit_source_obj[field_name] = new_val
                                self.update_render()
                    # Enter key (manual refresh if not in manual mode)
                    elif '\n' in data or '\r' in data:
                        if self.live:
                            self.update_render()
                    # Debug: uncomment to see raw sequences in log
                    # elif data.startswith('\x1b'):
                    #     self.add_app_log(f"DEBUG: Unknown seq: {repr(data)}")
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    def _refresh_task(self):
        """Background task to refresh UI (for uptime counter)"""
        while not self._stop_event.is_set():
            if self.live:
                try:
                    self.update_render()
                except Exception:
                    pass
            time.sleep(1)

    def start(self, screen: bool = True):
        self.update_render()
        self.live = Live(self.layout, console=self.console, refresh_per_second=4, screen=screen)
        self.live.start()

        # Start periodic refresh thread
        self._stop_event = threading.Event()
        self._refresh_thread = threading.Thread(target=self._refresh_task, daemon=True)
        self._refresh_thread.start()

        # Start input thread
        self._input_thread = threading.Thread(target=self._input_task, daemon=True)
        self._input_thread.start()

    def stop(self):
        if hasattr(self, "_stop_event"):
            self._stop_event.set()
        if hasattr(self, "_refresh_thread"):
            try:
                self._refresh_thread.join(timeout=1)
            except Exception:
                pass
        if hasattr(self, "_input_thread"):
            try:
                self._input_thread.join(timeout=1)
            except Exception:
                pass

        if self.live:
            self.live.stop()
            self.live = None

ui_instance: Optional[UI] = None

def get_ui(config_path: str = "config.yaml", config_manager=None) -> UI:
    global ui_instance
    if ui_instance is None:
        ui_instance = UI(config_path, config_manager)
    return ui_instance

class UILogHandler(logging.Handler):
    def __init__(self, ui: UI):
        super().__init__()
        self.ui = ui

    def emit(self, record):
        try:
            msg = self.format(record)
            self.ui.add_app_log(msg)
        except Exception:
            self.handleError(record)
