import os
import subprocess

from .core import IS_FULLY_INSTALLED_FILE, PROJECT_DIR

INSTALL_SCRIPT = os.path.join(PROJECT_DIR, "install.sh")


def full_install():
    try:
        result = subprocess.run([INSTALL_SCRIPT], check=False)

        if result.returncode != 0:
            print(f"[-] The installation failed with error code: {result.returncode}")
            return False
        else:
            print("[+] search_vulns was installed successfully")
            # create file to signal full installation
            with open(IS_FULLY_INSTALLED_FILE, "w") as f:
                pass
    except OSError:
        print(f"[-] The installation failed to run the installation script.")
        return False

    return True
