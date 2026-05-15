import threading
import re
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.logging import RichHandler
import logging

class UI:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()

        self.app_logs = []
        self.core_logs = []
        self.max_logs = 100

        self.lock = threading.Lock()
        self.live: Optional[Live] = None

        self._setup_layout()

    def _setup_layout(self):
        self.layout.split(
            Layout(name="main", ratio=1),
            Layout(name="footer", size=1),
        )
        self.layout["main"].split_row(
            Layout(name="left", ratio=7),
            Layout(name="status", ratio=3),
        )
        self.layout["left"].split(
            Layout(name="app", ratio=1),
            Layout(name="core", ratio=1),
        )

        self.mode = "TESTING"
        self.profile_name = "None"
        self.health_status = "OK"
        self.health_color = "green"

        self.start_time = datetime.now()
        self.sources = []
        self.last_update = None
        self.test_results = []
        self.core_type = "None"

    def _clean_name(self, name: str) -> str:
        if not name:
            return ""
        # Remove characters that are likely emojis or "junk"
        # Keep word characters (including unicode), spaces, and basic punctuation
        cleaned = re.sub(r'[^\w\s\.,\-_\[\]\(\)\+\/\!\?]', '', name)
        # Also handle multiple spaces that might result from removal
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.strip()

    def _get_panel(self, logs, title):
        content = Text()
        for log in logs[-20:]: # Show last 20 lines
            content.append(log + "\n")
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

        padding_center = (console_width - len(self.mode) - 2 - len(profile_str)) // 2
        if padding_center > 0:
            footer_content.append(" " * padding_center)
        footer_content.append(profile_text)

        padding_right = console_width - len(footer_content) - len(health_str)
        if padding_right > 0:
            footer_content.append(" " * padding_right)
        footer_content.append(health_text)

        return footer_content

    def _get_status_panel(self):
        content = Text()

        status_width = int(self.console.width * 0.3) - 4
        if status_width < 20: status_width = 20

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
            content.append("Test Results:\n", style="bold magenta")
            # Show top 10 results
            for p in self.test_results[:10]:
                name = self._clean_name(p.comment or p.host)
                is_current = name == self.profile_name

                ping = p.latency
                if ping is None:
                    ping_str = "TIMEOUT"
                    ping_style = "red"
                elif ping < 200:
                    ping_str = f"{ping}ms"
                    ping_style = "green"
                elif ping < 500:
                    ping_str = f"{ping}ms"
                    ping_style = "yellow"
                else:
                    ping_str = f"{ping}ms"
                    ping_style = "red"

                prefix = "> " if is_current else "  "

                # Calculate space for name
                # available = status_width - len(prefix) - len(ping_str) - 1 (min space)
                max_name_len = status_width - len(prefix) - len(ping_str) - 1
                if len(name) > max_name_len:
                    name = name[:max_name_len-3] + "..."

                # Padding to right-align ping
                padding_len = status_width - len(prefix) - len(name) - len(ping_str)
                if padding_len < 1: padding_len = 1
                padding = " " * padding_len

                line = Text()
                line.append(prefix, style="bold blink" if is_current else "")
                line.append(name, style="bold white" if is_current else "")
                line.append(padding)
                line.append(ping_str, style=ping_style)
                content.append(line)
                content.append("\n")

        return Panel(content, title="Status", border_style="green")

    def update_render(self):
        with self.lock:
            self.layout["app"].update(self._get_panel(self.app_logs, "Application Logs"))
            self.layout["core"].update(self._get_panel(self.core_logs, "Core (Sing-box/Xray) Logs"))
            self.layout["status"].update(self._get_status_panel())
            self.layout["footer"].update(self._get_footer())

    def set_status_data(self, sources=None, last_update=None, test_results=None):
        with self.lock:
            if sources is not None:
                self.sources = sources
            if last_update is not None:
                self.last_update = last_update
            if test_results is not None:
                self.test_results = test_results
        if self.live:
            self.update_render()

    def set_mode(self, mode: str):
        with self.lock:
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

    def add_app_log(self, message: str):
        with self.lock:
            self.app_logs.append(message)
            if len(self.app_logs) > self.max_logs:
                self.app_logs.pop(0)
        if self.live:
            self.update_render()

    def add_core_log(self, message: str):
        with self.lock:
            self.core_logs.append(message)
            if len(self.core_logs) > self.max_logs:
                self.core_logs.pop(0)
        if self.live:
            self.update_render()

    def start(self, screen: bool = True):
        self.update_render()
        self.live = Live(self.layout, console=self.console, refresh_per_second=4, screen=screen)
        self.live.start()

    def stop(self):
        if self.live:
            self.live.stop()
            self.live = None

ui_instance: Optional[UI] = None

def get_ui() -> UI:
    global ui_instance
    if ui_instance is None:
        ui_instance = UI()
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
