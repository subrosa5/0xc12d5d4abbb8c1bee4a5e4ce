"""Archive native binaries with offline instructions and format/security documentation."""

import json
import platform
import subprocess
import sys
import zipfile
from hashlib import sha256
from importlib.metadata import distribution
from pathlib import Path

root = Path(__file__).resolve().parent.parent
suffix = f"{platform.system().lower()}-{platform.machine().lower()}"
extension = ".exe" if platform.system() == "Windows" else ""
destination = root / "dist" / f"x12-native-{suffix}.zip"
with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
    from x12 import __version__

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True))
    archive.writestr(
        "BUILD.json",
        json.dumps(
            {
                "version": __version__,
                "commit": commit,
                "source_dirty": dirty,
                "platform": platform.system(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "pycryptodome": distribution("pycryptodome").version,
            },
            indent=2,
        )
        + "\n",
    )
    for name in ("x12", "x12-recover", "x12-desktop"):
        archive.write(root / "dist/native" / f"{name}-{suffix}{extension}", name + extension)
    for name in (
        "README.md",
        "SECURITY.md",
        "LICENSE",
        "RECOVERY.md",
        "THIRD_PARTY.md",
        "docs/format-v1.md",
        "docs/format-v2.md",
        "docs/device-protocol.md",
    ):
        archive.write(root / name, name)
    for package in ("pycryptodome", "pyinstaller", "pyinstaller-hooks-contrib"):
        metadata = distribution(package)
        for item in metadata.files or []:
            if any(part in str(item).lower() for part in ("license", "copying", "notice")):
                source = Path(metadata.locate_file(item))
                if source.is_file() and source.stat().st_size < 1024 * 1024:
                    archive.write(source, f"third-party-licenses/{package}/{item.name}")
    base = Path(sys.base_prefix)
    candidates = [
        base / "LICENSE",
        base / "LICENSE.txt",
        base / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/LICENSE.txt",
    ]
    candidates += list((base / "lib").glob("tcl*/license.terms"))
    candidates += list((base / "lib").glob("tk*/license.terms"))
    for index, source in enumerate(candidates):
        if source.is_file():
            archive.write(source, f"third-party-licenses/runtime-{index}-{source.name}")
print(destination)
destination.with_suffix(".sha256").write_text(
    f"{sha256(destination.read_bytes()).hexdigest()}  {destination.name}\n"
)
