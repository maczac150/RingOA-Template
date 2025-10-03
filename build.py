#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
from pathlib import Path
import platform


# ===== Utility =====
def run(cmd, cwd=None, use_sudo=False):
    if use_sudo and platform.system() != "Windows":
        cmd = ["sudo"] + cmd
    print(">>", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def require(tool):
    if shutil.which(tool) is None:
        raise RuntimeError(f"Required tool not found in PATH: {tool}")


def has_flag(args, flag):
    return any(a == flag for a in args)


def get_parallel(args):
    par = os.cpu_count() or 1
    for x in args:
        if x.startswith("--par="):
            val = x.split("=", 1)[1]
            try:
                par = int(val)
                if par < 1:
                    par = 1
            except ValueError:
                print("Error: Invalid value for --par argument. Must be an integer.")
                sys.exit(1)
    return par


def split_args(argv):
    if "--" in argv:
        idx = argv.index("--")
        main_args = argv[:idx]
        cmake_args = argv[idx + 1:]
    else:
        main_args = argv
        cmake_args = []
    return main_args, cmake_args


def already_sets_build_type(cmake_args):
    for a in cmake_args:
        if a.startswith("-DCMAKE_BUILD_TYPE=") or "CMAKE_BUILD_TYPE" in a:
            return True
    return False


def compute_build_type(main_args):
    if "--debug" in main_args or "--Debug" in main_args:
        return "Debug"
    if "--profile" in main_args or "--Profile" in main_args:
        return "RelWithDebInfo"
    return "Release"


def get_install_args(args):
    """Returns (do_install, prefix_path_or_None, use_sudo)"""
    use_sudo = has_flag(args, "--sudo")
    for x in args:
        if x.startswith("--install="):
            prefix = os.path.abspath(os.path.expanduser(x.split("=", 1)[1]))
            return True, prefix, use_sudo
    if has_flag(args, "--install"):
        return True, None, use_sudo
    return False, None, use_sudo


def choose_build_dir(build_type):
    return Path("out/build/linux")


def user_specified_generator(cmake_args):
    for a in cmake_args:
        if a == "-G" or a.startswith("-G"):
            return True
    return False


def ensure_dirs(paths):
    for p in paths:
        if not p.exists():
            print(f"Creating: {p}")
            run(["cmake", "-E", "make_directory", str(p)])
        else:
            print(f"Exists:   {p}")


def create_data_dirs():
    dir_path = Path(__file__).resolve().parent
    to_create = [
        "data/test",
        "data/bench",
        "data/logs",
    ]
    ensure_dirs([dir_path / p for p in to_create])


# ===== Setup Phase =====
def Setup(par, main_args, cmake_args, *, create_project_dirs=False, ringoa_only=False):
    require("git")
    require("cmake")

    try:
        import thirdparty.getRingOA as getRingOA
    except ImportError:
        print("Error: Could not find 'thirdparty/getRingOA'.")
        sys.exit(1)

    debug = has_flag(main_args, "--debug")
    use_sudo = has_flag(main_args, "--sudo")

    if ringoa_only:
        print("== Setup: RingOA only ==")
    else:
        print("== Setup: cryptoTools, Boost & RingOA ==")

    getRingOA.getRingOA(
        par=par,
        debug=debug,
        use_sudo=use_sudo,
        ringoa_only=ringoa_only,
        extra_cmake_args=cmake_args,
    )

    if create_project_dirs and not ringoa_only:
        print("== Setup: Creating project data directories ==")
        create_data_dirs()

    print("== Setup completed ==")


# ===== Build/Install Phase =====
def Build(project_name, main_args, cmake_args, par):
    require("cmake")

    build_type = compute_build_type(main_args)
    build_dir = choose_build_dir(build_type)

    generator_opts = []
    if not user_specified_generator(cmake_args):
        if shutil.which("ninja"):
            generator_opts = ["-G", "Ninja"]
        else:
            print("Note: 'ninja' not found. Falling back to default CMake generator.")

    cfg_args = list(cmake_args)
    if not already_sets_build_type(cfg_args):
        cfg_args.append(f"-DCMAKE_BUILD_TYPE={build_type}")
    cfg_args.append("-DCMAKE_CXX_FLAGS=-fdiagnostics-color=always")

    do_install, install_prefix, use_sudo = get_install_args(main_args)
    if do_install and install_prefix:
        cfg_args.append(f"-DCMAKE_INSTALL_PREFIX={install_prefix}")

    build_cmd = ["cmake", "--build", str(build_dir)]
    if par and par > 1:
        build_cmd += ["--parallel", str(par)]
    install_cmd = ["cmake", "--install", str(build_dir)]

    print("\n======= build.py (" + project_name + ") ==========")
    print("Configure Dir:", str(build_dir))
    print("CMake Args:   ", " ".join(cfg_args))
    print("Generator:    ", " ".join(generator_opts)
          if generator_opts else "(default)")
    print("Build Type:   ", build_type)
    print("Parallel:     ", par)
    print("Install:      ",
          f"{do_install} (prefix={install_prefix or '(cmake default)'})")
    print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n")

    try:
        run(["cmake", "-E", "make_directory", str(build_dir)])
        configure_cmd = ["cmake", "-S", ".", "-B",
                         str(build_dir)] + generator_opts + cfg_args
        run(configure_cmd)
        run(build_cmd)
        if do_install:
            print("== Installing project ==")
            run(install_cmd, use_sudo=use_sudo)
    except subprocess.CalledProcessError as e:
        print(f"\nError during build: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"\nPrerequisite error: {e}")
        sys.exit(1)


# ===== CLI =====
def help_msg():
    print(
        """
Usage:
  python build.py [options] [-- cmake_args]

Options:
  --setup             Fetch/build/install third-party deps (cryptoTools/Boost/RingOA) and create project data dirs.
  --setup-ringoa      Fetch/build/install RingOA only (skip cryptoTools/Boost).
  --install           Run 'cmake --install' using CMake's default prefix (e.g. /usr/local).
  --install=PATH      Configure with -DCMAKE_INSTALL_PREFIX=PATH, then run 'cmake --install'.
  --sudo              Use sudo for the install step.
  --par=N             Parallel build with N jobs (default: num cores).
  --debug             Debug build.
  --profile           Profile build.
  --help              Show this help.
  --                  Args after '--' go directly to CMake configure.

Examples:
  python build.py --setup
  python build.py --setup-ringoa
  python build.py --par=8
  python build.py --install                    # install into default prefix (may need --sudo)
  python build.py --install=$HOME/.local       # install into a custom prefix
  python build.py --install -- -DMY_OPT=ON     # install with extra CMake options
"""
    )


def main(project_name):
    argv = sys.argv[1:]
    main_args, cmake_args = split_args(argv)

    if has_flag(main_args, "--help"):
        help_msg()
        return

    par = get_parallel(main_args)

    if has_flag(main_args, "--setup"):
        Setup(par, main_args, cmake_args, create_project_dirs=True)
    elif has_flag(main_args, "--setup-ringoa"):
        Setup(par, main_args, cmake_args, ringoa_only=True)
    else:
        Build(project_name, main_args, cmake_args, par)


if __name__ == "__main__":
    main("SampleProject")
