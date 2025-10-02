#!/usr/bin/env python3
import platform
import shutil
import subprocess
from pathlib import Path


def run(cmd, cwd=None):
    print(">>", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def pyexe():
    return shutil.which("python3") or shutil.which("python") or "python3"


def getCryptoTools(par: int, build_cryptoTools: bool, setup_boost: bool, setup_relic: bool,
                   debug: bool = False, use_sudo: bool = False):
    cwd = Path(__file__).resolve().parent
    repo_dir = cwd / "cryptoTools"
    staged_prefix = cwd / "unix"

    commit = "2bf5fe84e19cadd9aeea5c191a08ac59e65b54e7"

    # clone & pin
    if not repo_dir.is_dir():
        run(["git", "clone", "https://github.com/ladnir/cryptoTools.git"], cwd=str(cwd))
    run(["git", "fetch", "--all", "--tags", "--prune"], cwd=str(repo_dir))
    run(["git", "checkout", "--quiet", commit], cwd=str(repo_dir))
    run(["git", "submodule", "update", "--init", "--recursive"], cwd=str(repo_dir))

    dbg = "--debug" if debug else ""

    # base args
    base = [pyexe(), "build.py", f"--par={par}", f"--install={staged_prefix}"]
    if dbg:
        base.append(dbg)
    if use_sudo and platform.system() != "Windows":
        base.append("--sudo")

    print("\n\n=========== getCryptoTools.py (fixed prefix) ================\n")

    # 1) Boost
    if setup_boost:
        cmd = base + ["--boost"]
        print("Boost setup command:\n ", " ".join(cmd))
        run(cmd, cwd=str(repo_dir))

    # 2) Relic
    if setup_relic:
        cmd = base + ["--relic"]
        print("Relic setup command:\n ", " ".join(cmd))
        run(cmd, cwd=str(repo_dir))

    # 3) cryptoTools itself
    if build_cryptoTools:
        cmd = base + [
            "-DFETCH_AUTO=ON",
            "-DENABLE_BOOST=ON",
            "-DFETCH_BOOST=OFF",
        ]
        if setup_relic:
            cmd += ["-DENABLE_RELIC=ON", "-DFETCH_RELIC=OFF"]
        else:
            cmd += ["-DENABLE_RELIC=OFF", "-DFETCH_RELIC=OFF"]

        print("cryptoTools build command:\n ", " ".join(cmd))
        run(cmd, cwd=str(repo_dir))

    print("\nvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n")


if __name__ == "__main__":
    getCryptoTools(
        par=1,
        build_cryptoTools=True,
        setup_boost=True,
        setup_relic=False,
        debug=False,
        use_sudo=False,
    )
