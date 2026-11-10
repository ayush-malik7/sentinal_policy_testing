"""Reference predictions for Sentinel's file-object allowlist contract.

ALLOW means this policy adds no denial. Other Linux checks still apply.
The fixture runner creates temporary ELF copies and never executes them.
"""

import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import NamedTuple


class FileIdentity(NamedTuple):
    major: int
    minor: int
    inode: int


def file_identity(path):
    """Follow links and identify the resolved regular file; errors propagate."""
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Contract v0 requires a regular executable file.")
    return FileIdentity(os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)


def expected_decision(allowed, target, *, in_scope=True,
                      earlier_denial=False, supported=True):
    """Predict our policy's decision from independently supplied facts.

    The caller must qualify the interface, native ELF format and fixture
    conditions. Unsupported cases are not graded as policy failures.
    """
    if not supported:
        return "UNSUPPORTED"
    if earlier_denial:
        return "DENY"
    if not in_scope:
        return "ALLOW"
    return "ALLOW" if target == allowed else "DENY"


# Expected answers come from the contract, not from the model's calculation.
FIXTURES = (
    ("allow_original", "original", "ALLOW"),
    ("deny_other", "other", "DENY"),
    ("allow_symlink", "symlink", "ALLOW"),
    ("allow_renamed", "rename", "ALLOW"),
    ("deny_copy", "copy", "DENY"),
)


def prepare_target(operation, a, b, directory):
    """Build a fixture without using or receiving its expected answer."""
    if operation == "original":
        return a
    if operation == "other":
        return b
    if operation == "symlink":
        target = directory / "alias_a"
        target.symlink_to(a)
        return target
    if operation == "rename":
        return a.rename(directory / "renamed_a")
    if operation == "copy":
        target = directory / "copy_a"
        shutil.copy2(a, target)
        return target
    raise ValueError("Unknown fixture operation: " + operation)


def run_fixtures():
    source = Path("/usr/bin/true")
    with source.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise RuntimeError("Fixture source /usr/bin/true is not ELF.")

    for name, operation, expected in FIXTURES:
        with tempfile.TemporaryDirectory(prefix="sentinel-model-") as folder:
            directory = Path(folder)
            a = directory / "program_a"
            b = directory / "program_b"
            shutil.copy2(source, a)
            shutil.copy2(source, b)

            # Keep A alive until this case finishes, including after rename.
            with a.open("rb"):
                allowed = file_identity(a)
                target = prepare_target(operation, a, b, directory)
                actual = expected_decision(allowed, file_identity(target))
                if actual != expected:
                    raise AssertionError(
                        f"{name}: expected {expected}, got {actual}"
                    )
                print(f"[MODEL PASS] {name}: {actual}", flush=True)

    print("Five model fixtures passed; temporary files removed.", flush=True)


if __name__ == "__main__":
    run_fixtures()
