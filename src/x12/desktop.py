"""Native local desktop interface. File contents never go to a web service."""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from x12 import __version__
from x12.storage import read_bounded
from x12.streaming import checkpoint_file, create_file, recover_file, rekey_file
from x12.vault import MAX_SHARE, VaultError

BG = "#10121b"
PANEL = "#1a1d2b"
TEXT = "#f0f1f6"
MUTED = "#a3a9be"
ACCENT = "#b5f89d"


class VaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        root.title("x12 · личный сейф")
        root.geometry("940x680")
        root.minsize(820, 620)
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.status = tk.StringVar(value="Готово · файлы обрабатываются на этом устройстве")
        self.buttons = []
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL)
        sidebar = tk.Frame(root, bg=PANEL, width=205)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="0x / x12", bg=PANEL, fg=ACCENT, font=("Menlo", 23, "bold")).pack(
            anchor="w", padx=24, pady=(32, 4)
        )
        tk.Label(
            sidebar, text="Файлы под вашим контролем", bg=PANEL, fg=MUTED, font=("Arial", 10)
        ).pack(anchor="w", padx=24, pady=(0, 30))
        self.content = tk.Frame(root, bg=BG)
        self.content.pack(side="top", fill="both", expand=True, padx=32, pady=28)
        for name, page in [
            ("Создать сейф", "create"),
            ("Восстановить", "recover"),
            ("Заменить участников", "rekey"),
            ("Проверки", "lab"),
        ]:
            button = tk.Button(
                sidebar,
                text=name,
                anchor="w",
                bg=PANEL,
                fg=TEXT,
                activebackground=BG,
                activeforeground=ACCENT,
                relief="flat",
                borderwidth=0,
                padx=24,
                pady=13,
                font=("Arial", 12),
                command=lambda target=page: self.show(target),
            )
            button.pack(fill="x")
            self.buttons.append(button)
        tk.Label(
            sidebar,
            text=f"v{__version__} · experimental\nНезависимого аудита ещё нет",
            justify="left",
            bg=PANEL,
            fg=MUTED,
            font=("Arial", 10),
        ).pack(side="bottom", anchor="w", padx=24, pady=24)
        self.show("create")
        self.root.after(100, self.poll)

    def label(self, text: str, size: int = 12, color: str = TEXT):
        label = tk.Label(
            self.content,
            text=text,
            bg=BG,
            fg=color,
            font=("Arial", size),
            anchor="w",
            justify="left",
            wraplength=630,
        )
        label.pack(fill="x", pady=(0, 16))
        return label

    def action(self, text: str, command: Callable):
        button = tk.Button(
            self.content,
            text=text,
            command=command,
            bg=ACCENT,
            fg=BG,
            activebackground="#d2ffbf",
            relief="flat",
            padx=22,
            pady=12,
            font=("Arial", 12, "bold"),
        )
        button.pack(anchor="w", pady=(12, 20))
        self.buttons.append(button)

    def choose_field(self, title: str, *, save=False, multiple=False) -> tk.StringVar:
        self.label(title, color=MUTED)
        frame = tk.Frame(self.content, bg=BG)
        frame.pack(fill="x", pady=(0, 14))
        value = tk.StringVar()
        entry = tk.Entry(
            frame,
            textvariable=value,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Arial", 11),
        )
        entry.pack(side="left", fill="x", expand=True, ipady=8)

        def choose():
            if multiple:
                paths = filedialog.askopenfilenames(parent=self.root, title=title)
                if paths:
                    self.selected_shares = [Path(p) for p in paths]
                    value.set(f"Выбрано долей: {len(paths)}")
            else:
                path = (
                    filedialog.asksaveasfilename(parent=self.root, title=title)
                    if save
                    else filedialog.askopenfilename(parent=self.root, title=title)
                )
                if path:
                    value.set(path)

        button = tk.Button(
            frame, text="Выбрать", command=choose, relief="flat", padx=12, pady=6, bg=PANEL, fg=TEXT
        )
        button.pack(side="left", padx=(8, 0))
        self.buttons.append(button)
        return value

    def show(self, page: str):
        if self.busy:
            return
        for child in self.content.winfo_children():
            child.destroy()
        self.buttons = [b for b in self.buttons if b.winfo_exists()]
        self.selected_shares = []
        titles = {
            "create": "Сохраните файл вместе с людьми, которым доверяете",
            "recover": "Верните доступ к файлу",
            "rekey": "Новый состав участников",
            "lab": "Проверьте, как работает восстановление",
        }
        self.label(titles[page], 23)
        if page == "lab":
            self.label(
                "Проверка использует вымышленные файлы. Ваши сейфы и ключи не читаются.",
                color=MUTED,
            )
            self.destination = self.choose_field("Новая папка отчёта", save=True)
            self.action("Запустить проверки", self.run_lab)
        else:
            self.source = self.choose_field("Исходный файл" if page == "create" else "Файл сейфа")
            if page != "create":
                self.choose_field("Файлы долей участников", multiple=True)
            self.destination = self.choose_field(
                "Новая папка сейфа" if page != "recover" else "Куда сохранить файл", save=True
            )
            if page != "recover":
                row = tk.Frame(self.content, bg=BG)
                row.pack(fill="x", pady=6)
                tk.Label(row, text="Для открытия нужны", bg=BG, fg=MUTED).pack(side="left")
                self.threshold = tk.IntVar(value=3)
                self.total = tk.IntVar(value=5)
                tk.Spinbox(row, from_=2, to=255, width=4, textvariable=self.threshold).pack(
                    side="left", padx=10
                )
                tk.Label(row, text="из", bg=BG, fg=MUTED).pack(side="left")
                tk.Spinbox(row, from_=2, to=255, width=4, textvariable=self.total).pack(
                    side="left", padx=10
                )
                self.label(
                    "У каждой доли будет свой пароль. Сохраните пароли отдельно от файлов.",
                    11,
                    MUTED,
                )
            if page == "rekey":
                self.label(
                    "Старые копии останутся читаемыми. Новый сейф получит новый ключ.", 11, MUTED
                )
            self.action(
                {
                    "create": "Создать сейф",
                    "recover": "Восстановить файл",
                    "rekey": "Создать новое поколение",
                }[page],
                lambda: self.run_vault(page),
            )
        self.progress = ttk.Progressbar(self.content, mode="indeterminate")
        self.progress.pack(fill="x", pady=(4, 12))
        tk.Label(
            self.content,
            textvariable=self.status,
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=630,
        ).pack(fill="x")

    def passwords(self, names: list[str], confirm: bool) -> list[bytes] | None:
        values = []
        for name in names:
            value = simpledialog.askstring(
                "Пароль доли", f"Пароль для {name} (от 12 байт):", show="*", parent=self.root
            )
            if value is None:
                return None
            if not 12 <= len(value.encode()) <= 1024:
                raise VaultError("Пароль должен содержать от 12 до 1024 байт UTF-8")
            if confirm and value != simpledialog.askstring(
                "Повтор пароля", f"Повторите: {name}", show="*", parent=self.root
            ):
                raise VaultError("Пароли не совпадают")
            values.append(value.encode())
        return values

    def run_vault(self, page: str):
        try:
            if not self.source.get() or not self.destination.get():
                raise VaultError("Выберите исходный файл и место сохранения")
            source, output = Path(self.source.get()), Path(self.destination.get())
            shares = list(self.selected_shares)
            old_passwords = None
            if page != "create":
                if not shares:
                    raise VaultError("Выберите файлы долей")
                old_passwords = self.passwords([p.name for p in shares], confirm=False)
                if old_passwords is None:
                    return
            if page != "recover":
                threshold, total = self.threshold.get(), self.total.get()
                if not 2 <= threshold <= total <= 255:
                    raise VaultError("Нужно: 2 ≤ порог ≤ число участников ≤ 255")
                new_passwords = self.passwords([f"участник {i}" for i in range(1, total + 1)], True)
                if new_passwords is None:
                    return

            def work():
                if page == "create":
                    create_file(source, output, new_passwords, threshold, total)
                else:
                    raw = [read_bounded(p, MAX_SHARE) for p in shares]
                    if page == "recover":
                        recover_file(source, raw, old_passwords, output)
                    else:
                        rekey_file(
                            source, raw, old_passwords, output, new_passwords, threshold, total
                        )
                if page != "recover":
                    checkpoint_file(output / "vault.x12", output / "version.checkpoint")
                return (
                    "Готово. Распределите доли и храните checkpoint отдельно."
                    if page != "recover"
                    else "Файл восстановлен, подлинность проверена."
                )

            self.start(work)
        except (ValueError, OSError, tk.TclError) as exc:
            messagebox.showerror("Не удалось начать", str(exc), parent=self.root)

    def run_lab(self):
        if not self.destination.get():
            messagebox.showerror("Нужна папка", "Выберите новую папку отчёта", parent=self.root)
            return
        target = Path(self.destination.get())

        def work():
            from x12.lab import run_lab

            code = run_lab(target)
            return (
                "Проверки пройдены. Отчёт сохранён."
                if code == 0
                else "Есть ошибки. Проверьте отчёт."
            )

        self.start(work)

    def start(self, work: Callable):
        self.busy = True
        self.status.set("Выполняется… Не закрывайте приложение.")
        for button in self.buttons:
            button.configure(state="disabled")
        self.progress.start(12)

        def worker():
            try:
                self.events.put((True, work()))
            except Exception as exc:
                self.events.put((False, str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            ok, text = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.progress.stop()
            for button in self.buttons:
                if button.winfo_exists():
                    button.configure(state="normal")
            self.status.set(text)
            if not ok:
                messagebox.showerror("Операция не завершена", text, parent=self.root)
        self.root.after(100, self.poll)

    def close(self):
        if self.busy:
            messagebox.showinfo(
                "Операция выполняется", "Дождитесь завершения операции.", parent=self.root
            )
            return
        self.root.destroy()


def main() -> int:
    if sys.argv[1:2] == ["__crash-worker"]:
        from x12._crash_worker import main as crash_worker

        crash_worker(sys.argv[2:])
        return 0
    if sys.argv[1:2] == ["--version"]:
        print(__version__)
        return 0
    root = tk.Tk()
    smoke = sys.argv[1:2] == ["--smoke-test"]
    if smoke:
        root.withdraw()
    app = VaultApp(root)
    if smoke:
        for page in ("create", "recover", "rekey", "lab"):
            app.show(page)
            root.update_idletasks()
        root.destroy()
        print("Desktop widgets initialized on all four pages.")
        return 0
    root.mainloop()
    return 0
