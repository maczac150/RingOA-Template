#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
from pathlib import Path


def run(cmd, cwd=None):
    """Run a shell command with echo"""
    print(">>", " ".join(map(str, cmd)))
    subprocess.run(cmd, cwd=cwd, check=True)


def pyexe():
    """Get python executable name"""
    return shutil.which("python3") or shutil.which("python") or "python3"


def getRingOA(par=None, debug=False, use_sudo=False):
    par = par or os.cpu_count()
    cwd = Path(__file__).resolve().parent
    unix_prefix = cwd / "unix"

    # ---------------------------
    # 1. cryptoTools & Boost setup
    # ---------------------------
    try:
        import thirdparty.getCryptoTools as getCryptoTools
    except ImportError:
        print("Error: getCryptoTools.py not found in thirdparty/")
        sys.exit(1)

    print("== Setup: cryptoTools & Boost (before RingOA) ==")
    getCryptoTools.getCryptoTools(
        par=par,
        build_cryptoTools=True,
        setup_boost=True,
        setup_relic=False,
        debug=debug,
        use_sudo=use_sudo,
    )

    # ---------------------------
    # 2. RingOA fetch
    # ---------------------------
    repo_dir = cwd / "RingOA"
    if not repo_dir.exists():
        run([
            "git", "clone",
            "git@github.com:u-tmk/RingOA-dev.git",
            str(repo_dir)
        ])
    else:
        print("== RingOA already cloned, pulling latest ==")
        run(["git", "pull"], cwd=repo_dir)

    # Update submodules
    run(["git", "submodule", "update", "--init", "--recursive"], cwd=repo_dir)

    # ---------------------------
    # 3. RingOA build & install
    # ---------------------------
    base = [pyexe(), "build.py", f"--par={par}", f"--install={unix_prefix}"]
    if debug:
        base.append("--debug")
    if use_sudo:
        base.append("--sudo")

    run(base, cwd=repo_dir)


if __name__ == "__main__":
    getRingOA()
