"""Build native offline binaries on the current OS; no cross-compilation claims."""

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--target", choices=["all", "cli", "recovery", "desktop"], default="all")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
names = {"cli": "x12", "recovery": "x12-recover", "desktop": "x12-desktop"}
suffix = f"{platform.system().lower()}-{platform.machine().lower()}"
output = root / "dist/native"
output.mkdir(parents=True, exist_ok=True)
for target, name in names.items():
    if args.target not in {"all", target}:
        continue
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--paths",
        str(root / "src"),
        "--collect-binaries",
        "Crypto",
        "--distpath",
        str(output),
        "--workpath",
        str(root / ".build" / name / "work"),
        "--specpath",
        str(root / ".build" / name),
        "--name",
        name,
        str(root / "tools" / f"{target}_entry.py"),
    ]
    subprocess.run(command, cwd=root, check=True)
    executable = output / (name + (".exe" if sys.platform == "win32" else ""))
    subprocess.run([str(executable), "--version"], check=True, timeout=30)
    destination = output / f"{name}-{suffix}{executable.suffix}"
    shutil.copy2(executable, destination)
    print(f"Built: {destination}")
