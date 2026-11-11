"""Internal synthetic crash-lab worker. Never used by vault creation or recovery."""

import sys
import time
from pathlib import Path
from unittest.mock import patch

from x12.storage import atomic_write


def main() -> None:
    root = Path(sys.argv[1])

    def before_publish(*_args: object, **_kwargs: object) -> None:
        # The parent kills this process after the temporary file has been fsynced
        # and before the final destination is linked into the directory.
        (root / "ready").write_text("ready", encoding="ascii")
        time.sleep(30)
        raise RuntimeError("Crash worker was not terminated by its parent")

    with patch("x12.storage.os.link", side_effect=before_publish):
        atomic_write(root / "output", b"synthetic crash fixture")


if __name__ == "__main__":
    main()
