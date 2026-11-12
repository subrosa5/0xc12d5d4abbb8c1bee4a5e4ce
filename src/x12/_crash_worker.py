"""Internal synthetic crash-lab worker. Never used by vault creation or recovery."""

import sys
import time
from pathlib import Path

from x12.storage import atomic_output


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0])
    stage = args[1] if len(args) > 1 else "before-publish"

    def before_publish(current: str) -> None:
        if current != stage:
            return
        # The parent kills this process after the temporary file has been fsynced
        # and before the final destination is linked into the directory.
        (root / "ready").write_text("ready", encoding="ascii")
        time.sleep(30)
        raise RuntimeError("Crash worker was not terminated by its parent")

    with atomic_output(root / "output", hook=before_publish) as handle:
        handle.write(b"synthetic crash fixture")


if __name__ == "__main__":
    main()
