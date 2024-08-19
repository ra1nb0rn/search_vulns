import os
from cpe_search.cpe_search import _load_config as _load_config_cpe_search

DEFAULT_CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'config.json')
CONFIG_FILE = DEFAULT_CONFIG_FILE

CONFIG = None

def _load_config(config_file=DEFAULT_CONFIG_FILE):
    '''Load config from file'''

    config = _load_config_cpe_search(config_file)
    config['cpe_search']['DATABASE'] = config['DATABASE']
    config['cpe_search']['NVD_API_KEY'] = config['NVD_API_KEY']

    global CONFIG    
    CONFIG = config
    return config



def get_config():
    global CONFIG
    if not CONFIG:
        CONFIG = _load_config()
    return CONFIG


def update_config_generic():
    global CONFIG
    CONFIG['DATABASE_BACKUP_FILE'] = CONFIG['DATABASE_NAME'] + '.bak'
    CONFIG['CPE_DATABASE_BACKUP_FILE'] = CONFIG['cpe_search']['DATABASE_NAME'] + '.bak'
    CONFIG['DEPRECATED_CPES_BACKUP_FILE'] = CONFIG['cpe_search']['DEPRECATED_CPES_FILE'] + '.bak'
    return CONFIG