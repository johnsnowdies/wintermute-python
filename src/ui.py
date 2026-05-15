import threading
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
            Layout(name="app", ratio=1),
            Layout(name="core", ratio=1),
        )

    def _get_panel(self, logs, title):
        content = Text()
        for log in logs[-20:]: # Show last 20 lines
            content.append(log + "\n")
        return Panel(content, title=title, border_style="blue")

    def update_render(self):
        with self.lock:
            self.layout["app"].update(self._get_panel(self.app_logs, "Application Logs"))
            self.layout["core"].update(self._get_panel(self.core_logs, "Core (Sing-box/Xray) Logs"))

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
