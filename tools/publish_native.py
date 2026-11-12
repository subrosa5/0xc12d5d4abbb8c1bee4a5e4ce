"""Attach verified archives only to a matching draft release."""

import json
import os
import re
import subprocess
import sys
import zipfile
from hashlib import sha256
from pathlib import Path

tag = sys.argv[1]
if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("Invalid release tag")
repository = os.environ["GITHUB_REPOSITORY"]
metadata = json.loads(
    subprocess.check_output(
        ["gh", "release", "view", tag, "--repo", repository, "--json", "isDraft,targetCommitish"],
        text=True,
    )
)
if not metadata["isDraft"] or metadata["targetCommitish"] != os.environ["GITHUB_SHA"]:
    raise SystemExit("Publication requires a draft targeting this exact source commit")
artifacts = []
for path in sorted(Path("dist").glob("x12-native-*.zip")):
    checksum = path.with_suffix(".sha256")
    expected = f"{sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
    if checksum.read_text() != expected:
        raise SystemExit("Archive checksum mismatch")
    with zipfile.ZipFile(path) as archive:
        build = json.loads(archive.read("BUILD.json"))
    if (
        build["commit"] != os.environ["GITHUB_SHA"]
        or build["source_dirty"]
        or tag != "v" + build["version"]
    ):
        raise SystemExit("Archive provenance mismatch")
    artifacts.extend([str(path), str(checksum)])
if not artifacts:
    raise SystemExit("No verified native archives")
subprocess.run(["gh", "release", "upload", tag, *artifacts, "--repo", repository], check=True)
