#!/usr/bin/env python3
"""
Setup script for search_vulns package.
Handles custom installation steps like git submodules and module initialization.
"""

import os
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.develop import develop
from setuptools.command.install import install
from setuptools.command.build_py import build_py


def run_module_installs():
    """Run installation scripts for all modules."""
    project_dir = Path(__file__).parent
    modules_dir = project_dir / "modules"
    
    if not modules_dir.exists():
        return
    
    import runpy
    
    for module_file in modules_dir.rglob("search_vulns_*.py"):
        module_script_dir = module_file.parent
        module_script_name = module_file.name
        
        try:
            globals_dict = runpy.run_path(str(module_file))
            os.chdir(module_script_dir)
            if 'install' in globals_dict and callable(globals_dict['install']):
                print(f'[+] Installing module at {module_file}')
                globals_dict['install']()
        except Exception as e:
            print(f"Error in {module_script_name}: {e}", file=sys.stderr)
        finally:
            os.chdir(project_dir)


def init_git_submodules():
    """Initialize and update git submodules."""
    project_dir = Path(__file__).parent
    git_dir = project_dir / ".git"
    
    if not git_dir.exists():
        print("[!] Not a git repository, skipping submodule initialization")
        print("[!] If installing from a package, submodules should already be included")
        return
    
    try:
        print("[+] Setting up git submodules")
        result = subprocess.run(
            ["git", "submodule", "init"],
            cwd=project_dir,
            check=False,
            capture_output=True,
            text=True
        )
        if result.returncode != 0 and "already initialized" not in result.stderr.lower():
            print(f"[!] Warning: git submodule init returned: {result.stderr}")
        
        result = subprocess.run(
            ["git", "submodule", "update", "--recursive"],
            cwd=project_dir,
            check=False,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"[!] Warning: git submodule update returned: {result.stderr}")
            print("[!] You may need to run 'git submodule update --init --recursive' manually")
    except FileNotFoundError:
        print("[!] Warning: git command not found. Submodules may not be initialized.")
    except Exception as e:
        print(f"[!] Warning: Could not initialize git submodules: {e}")


class PostInstallCommand(install):
    """Post-installation command to run custom setup steps."""
    
    def run(self):
        install.run(self)
        self._post_install()
    
    def _post_install(self):
        """Run post-installation steps."""
        project_dir = Path(__file__).parent
        
        # Initialize git submodules
        init_git_submodules()
        
        # Run module installations
        print("[+] Running installation scripts of modules ...")
        run_module_installs()
        
        print("\n[!] Note: To create local databases, run:")
        print("    search_vulns -u")
        print("    or for a full update:")
        print("    search_vulns --full-update")


class PostDevelopCommand(develop):
    """Post-installation command for development mode."""
    
    def run(self):
        develop.run(self)
        self._post_install()
    
    def _post_install(self):
        """Run post-installation steps."""
        project_dir = Path(__file__).parent
        
        # Initialize git submodules
        init_git_submodules()
        
        # Run module installations
        print("[+] Running installation scripts of modules ...")
        run_module_installs()


class BuildPyCommand(build_py):
    """Build command that ensures submodules are initialized before building."""
    
    def run(self):
        # Initialize submodules before building
        init_git_submodules()
        build_py.run(self)


# Read pyproject.toml for metadata (setuptools will handle it automatically)
# This setup.py is mainly for custom installation commands
# All project metadata is defined in pyproject.toml
if __name__ == "__main__":
    setup(
        cmdclass={
            'build_py': BuildPyCommand,
            'install': PostInstallCommand,
            'develop': PostDevelopCommand,
        },
    )

