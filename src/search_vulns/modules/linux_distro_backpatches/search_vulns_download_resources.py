import os
import shutil

from search_vulns.modules.utils import download_github_folder

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
GITHUB_REPO_URL_UBUNTU = "https://github.com/aquasecurity/vuln-list.git"
GITHUB_REPO_URL_REDHAT = "https://github.com/aquasecurity/vuln-list-redhat"
UBUNTU_DATAFEED_DIR = os.path.join(SCRIPT_DIR, "ubuntu", "ubuntu_data_feeds")
REDHAT_DATAFEED_DIR = os.path.join(SCRIPT_DIR, "redhat", "vuln-list-redhat")


def full_update(productdb_config, vulndb_config, module_config, stop_update):
    # download Red Hat data feeds
    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)
    download_github_folder(GITHUB_REPO_URL_REDHAT, "api", REDHAT_DATAFEED_DIR)

    # download Ubuntu data feeds
    if os.path.isdir(UBUNTU_DATAFEED_DIR):
        shutil.rmtree(UBUNTU_DATAFEED_DIR)
    download_github_folder(GITHUB_REPO_URL_UBUNTU, "ubuntu", UBUNTU_DATAFEED_DIR)

    return True, []
