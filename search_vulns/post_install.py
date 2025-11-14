#!/usr/bin/env python3
"""
Post-installation script for search_vulns package.
This script runs module installation steps after the package is installed.
"""

import os
import subprocess
import sys
from pathlib import Path

import runpy


def run_module_installs():
    """Run installation scripts for all modules."""
    # Get the installed package directory
    # When installed, __file__ will be in site-packages/search_vulns/
    package_dir = Path(__file__).parent
    modules_dir = package_dir / "modules"

    if not modules_dir.exists():
        print("[!] Modules directory not found, skipping module installations")
        return

    original_cwd = os.getcwd()

    try:
        for module_file in modules_dir.rglob("search_vulns_*.py"):
            module_script_dir = module_file.parent
            module_script_name = module_file.name

            try:
                globals_dict = runpy.run_path(str(module_file))
                os.chdir(module_script_dir)
                if "install" in globals_dict and callable(globals_dict["install"]):
                    print(f"[+] Installing module at {module_file}")
                    globals_dict["install"]()
            except Exception as e:
                print(f"Error in {module_script_name}: {e}", file=sys.stderr)
            finally:
                os.chdir(original_cwd)
    finally:
        os.chdir(original_cwd)


def init_git_submodules():
    """Initialize and update git submodules."""
    # When installed, we can't easily find the git repo
    # This is mainly for development installs
    package_dir = Path(__file__).parent
    # Try to find the project root by going up from site-packages
    # This is tricky, so we'll skip it for installed packages
    # and only run it if we can find a .git directory
    possible_roots = [
        package_dir.parent.parent.parent,  # site-packages -> lib -> pythonX.X -> project
        package_dir.parent.parent,  # Alternative path
    ]

    for project_dir in possible_roots:
        git_dir = project_dir / ".git"
        if git_dir.exists():
            try:
                print("[+] Setting up git submodules")
                result = subprocess.run(
                    ["git", "submodule", "init"],
                    cwd=project_dir,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0 and "already initialized" not in result.stderr.lower():
                    print(f"[!] Warning: git submodule init returned: {result.stderr}")

                result = subprocess.run(
                    ["git", "submodule", "update", "--recursive"],
                    cwd=project_dir,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    print(f"[!] Warning: git submodule update returned: {result.stderr}")
                    print("[!] You may need to run 'git submodule update --init --recursive' manually")
                return
            except FileNotFoundError:
                print("[!] Warning: git command not found. Submodules may not be initialized.")
            except Exception as e:
                print(f"[!] Warning: Could not initialize git submodules: {e}")
            break


def main():
    """Main post-install function."""
    print("[+] Running post-installation steps for search_vulns...")

    # Initialize git submodules (mainly for development installs)
    init_git_submodules()

    # Run module installations
    print("[+] Running installation scripts of modules ...")
    run_module_installs()

    print("\n[!] Note: To create local databases, run:")
    print("    search_vulns -u")
    print("    or for a full update:")
    print("    search_vulns --full-update")


if __name__ == "__main__":
    main()

