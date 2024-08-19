import os
import shutil
import json

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

from cpe_search.cpe_search import update as update_cpe
from .update_generic import *
from cpe_search.cpe_search import get_all_cpes

async def handle_cpes_update(config, nvd_api_key=None):
    # backup database and deprecated cpes file
    if os.path.isfile(config['cpe_search']['DATABASE_NAME']):
        shutil.move(config['cpe_search']['DATABASE_NAME'], config['CPE_DATABASE_BACKUP_FILE'])
    if os.path.isfile(config['cpe_search']['DEPRECATED_CPES_FILE']):
        shutil.move(config['cpe_search']['DEPRECATED_CPES_FILE'], config['DEPRECATED_CPES_BACKUP_FILE'])
    if config['DATABASE']['TYPE'] == 'mariadb':
       backup_mariadb_database(config['cpe_search']['DATABASE_NAME'], config)

    success = await update_cpe(nvd_api_key, config['cpe_search'])
    if not success:
        if os.path.isfile(config['CPE_DATABASE_BACKUP_FILE']):
            shutil.move(config['CPE_DATABASE_BACKUP_FILE'], config['cpe_search']['DATABASE_NAME'])
        if os.path.isfile(config['DEPRECATED_CPES_BACKUP_FILE']):
            shutil.move(config['DEPRECATED_CPES_BACKUP_FILE'], config['cpe_search']['DEPRECATED_CPES_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE) and config['DATABASE']['TYPE'] == 'mariadb':
            restore_mariadb(config)
    else:
        if os.path.isfile(config['CPE_DATABASE_BACKUP_FILE']):
            os.remove(config['CPE_DATABASE_BACKUP_FILE'])
        if os.path.isfile(config['DEPRECATED_CPES_BACKUP_FILE']):
            os.remove(config['DEPRECATED_CPES_BACKUP_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE):
            os.remove(MARIADB_BACKUP_FILE)

    return not success


def restore_mariadb(config):
        with open(MARIADB_BACKUP_FILE, 'rb') as f:
            mariadb_backup_data = f.read()
        restore_call = ['mariadb', '-u', config['DATABASE']['USER'],
                        '-h', config['DATABASE']['HOST'],
                        '-P', str(config['DATABASE']['PORT'])]
        if config['DATABASE']['PASSWORD']:
            restore_call.append(f"-p{config['DATABASE']['PASSWORD']}")
        restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
        if restore_call_run.returncode != 0:
            print('[-] Failed to restore MariaDB')
        else:
            print('[+] Restored MariaDB from backup')

        # Restore failed b/c database is down -> not delete backup file
        # check whether database is up by trying to get a connection
        try:
            get_database_connection(config['DATABASE'], config['cpe_search']['DATABASE_NAME'])
        except:
            print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
            print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
        else:
            os.remove(MARIADB_BACKUP_FILE)