import os
import shutil
import sqlite3
import json

try:  # use ujson if available
    import ujson as json
except ModuleNotFoundError:
    import json

from cpe_search.cpe_search import update as update_cpe
from .update_generic import *

async def handle_cpes_update(nvd_api_key=None):
    if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
        shutil.move(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
    if os.path.isfile(CONFIG['cpe_search']['DEPRECATED_CPES_FILE']):
        shutil.move(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'], CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
       backup_mariadb_database(CONFIG['cpe_search']['DATABASE_NAME'])

    success = await update_cpe(nvd_api_key, CONFIG['cpe_search'])
    if not success:
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            shutil.move(CONFIG['CPE_DATABASE_BACKUP_FILE'], CONFIG['cpe_search']['DATABASE_NAME'])
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            shutil.move(CONFIG['DEPRECATED_CPES_BACKUP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE) and CONFIG['DATABASE']['TYPE'] == 'mariadb':
            with open(MARIADB_BACKUP_FILE, 'rb') as f:
                mariadb_backup_data = f.read()
            restore_call = ['mariadb', '-u', CONFIG['DATABASE']['USER'],
                            '-h', CONFIG['DATABASE']['HOST'],
                            '-P', str(CONFIG['DATABASE']['PORT'])]
            if CONFIG['DATABASE']['PASSWORD']:
                restore_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
            restore_call_run = subprocess.run(restore_call, input=mariadb_backup_data)
            if restore_call_run.returncode != 0:
                print('[-] Failed to restore MariaDB')
            else:
                print('[+] Restored MariaDB from backup')

            # Restore failed b/c database is down -> not delete backup file
            # check whether database is up by trying to get a connection
            try:
                get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
            except:
                print('[!] MariaDB seems to be down. The backup file wasn\'t deleted. To restore manually from the file, run the following command:')
                print(' '.join(restore_call+['<', MARIADB_BACKUP_FILE, '&&', 'rm', MARIADB_BACKUP_FILE]))
            else:
                os.remove(MARIADB_BACKUP_FILE)
    else:
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            os.remove(CONFIG['CPE_DATABASE_BACKUP_FILE'])
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            os.remove(CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
        if os.path.isfile(MARIADB_BACKUP_FILE):
            os.remove(MARIADB_BACKUP_FILE)

    return not success