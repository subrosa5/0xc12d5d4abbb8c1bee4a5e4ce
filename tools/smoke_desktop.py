"""Exercise native widget creation without displaying a window or touching user files."""

import tkinter as tk

from x12.desktop import VaultApp

root = tk.Tk()
root.withdraw()
app = VaultApp(root)
for page in ["create", "recover", "rekey", "lab"]:
    app.show(page)
    root.update_idletasks()
assert not app.busy
root.destroy()
print("Desktop widgets initialized on all four pages.")
