#!/usr/bin/env python3
"""
CLI entry point wrapper for search_vulns.
This module allows search_vulns to be installed as a pip package.
"""

import sys
import os

# Add the package directory to the path so imports work correctly
# When installed as a package, __file__ points to the installed location
package_dir = os.path.dirname(os.path.abspath(__file__))
if package_dir not in sys.path:
    sys.path.insert(0, package_dir)

# Try to import and run the main function from search_vulns.py
try:
    from search_vulns import main
except ImportError as e:
    # Provide helpful error message if modules are missing
    if "modules.cpe_search" in str(e) or "No module named" in str(e):
        print("Error: Required modules are missing. This usually means git submodules are not initialized.", file=sys.stderr)
        print("Please run the following commands:", file=sys.stderr)
        print("  git submodule update --init --recursive", file=sys.stderr)
        print("  pip install -e .", file=sys.stderr)
        sys.exit(1)
    raise

if __name__ == "__main__":
    main()

