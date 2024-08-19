#!/usr/bin/env python3

import os
import shlex
import subprocess
import sys

from .update_nvd import update_vuln_db
from .update_cpes import handle_cpes_update, add_new_cpes_to_db
from .update_generic import *
from .update_debian import update_vuln_debian_db
from .update_ubuntu import update_vuln_ubuntu_db
from .update_redhat import update_vuln_redhat_db
from .update_distributions_generic import (
    NEW_CPES_INFOS,
    init_manual_mapping,
    load_all_cpes,
    create_table_distribution_codename_version_mapping,
    initialize_packagename_cpe_mapping
)
from search_vulns_modules.config import update_config_generic, _load_config

CONFIG = {}


def migrate_to_mariadb(config_file):
    try:
        print('[+] Migrating from SQLite to MariaDB (takes around 2 minutes)...')
        return_code = subprocess.call('./migrate_sqlite_to_mariadb.sh %s %s %s' % (shlex.quote(CONFIG['DATABASE_NAME']), shlex.quote(CONFIG['cpe_search']['DATABASE_NAME']), config_file), shell=True, stderr=subprocess.DEVNULL)
        if return_code != 0:
            raise(Exception('Migration of database failed'))
        os.remove(MARIADB_BACKUP_FILE)
        os.remove(CONFIG['DATABASE_NAME'])
        os.remove(CONFIG['cpe_search']['DATABASE_NAME'])
    except:
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


def backup_mariadb(config_file):
    try:
        # check whether database exists
        get_database_connection(CONFIG['DATABASE'], CONFIG['DATABASE_NAME'])
        get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
    except:
        pass
    else:
        # backup MariaDB
        backup_call = ['mariadb-dump',
                        '-u', CONFIG['DATABASE']['USER'],
                        '-h', CONFIG['DATABASE']['HOST'],
                        '-P', str(CONFIG['DATABASE']['PORT']),
                        '--add-drop-database', '--add-locks',
                        '-B', CONFIG['DATABASE_NAME'],
                        '-B', CONFIG['cpe_search']['DATABASE_NAME'],
                        '-r', MARIADB_BACKUP_FILE]
        if CONFIG['DATABASE']['PASSWORD']:
            backup_call.append(f"-p{CONFIG['DATABASE']['PASSWORD']}")
        return_code = subprocess.call(backup_call, stderr=subprocess.DEVNULL)
        if return_code != 0:
            print(f'[-] MariaDB backup failed')
    # expand paths
    CONFIG['DATABASE_NAME'] = os.path.join(os.path.dirname(os.path.abspath(config_file)), CONFIG['DATABASE_NAME'])
    CONFIG['cpe_search']['DATABASE_NAME'] = os.path.join(os.path.dirname(os.path.abspath(config_file)), CONFIG['cpe_search']['DATABASE_NAME'])
    

def full_update(nvd_api_key, config_file):
    if not nvd_api_key:
        nvd_api_key = os.getenv('NVD_API_KEY')
        if (not nvd_api_key) and CONFIG:
            nvd_api_key = CONFIG.get('NVD_API_KEY', None)

    # always try get to get an old CVEID<->EDBID mapping to speed up update
    if not os.path.isfile(CONFIG['CVE_EDB_MAP_FILE']):
        try:
            with open(os.devnull, 'w') as f:
                subprocess.call("wget -q %s -O %s" % (shlex.quote(CVE_EDB_MAP_ARTIFACT_URL),
                                    shlex.quote(CONFIG['CVE_EDB_MAP_FILE'])), shell=True, stdout=f,
                                    stderr=subprocess.STDOUT)
        except:
            pass

    # backup database
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
        backup_mariadb_database(CONFIG['DATABASE_NAME'], CONFIG)
    elif os.path.isfile(CONFIG['DATABASE_NAME']):
        shutil.move(CONFIG['DATABASE_NAME'], CONFIG['DATABASE_BACKUP_FILE'])

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    print("[+] Updating stored software information")
    error = loop.run_until_complete(handle_cpes_update(CONFIG, nvd_api_key))
    if error:
        print("[-] Error updating stored software information")
        sys.exit(1)
    print("[+] Updating vulnerability database")
    error = loop.run_until_complete(update_vuln_db(nvd_api_key, config=CONFIG, config_file=config_file))
    if error:
        print(error)
        sys.exit(1)

    # fill the mapping dictionary with hardcoded information
    init_manual_mapping()
    # load all cpes from cpe_search database
    load_all_cpes(CONFIG)
    # add information from a debian source
    error = initialize_packagename_cpe_mapping()
    if error:
        print(error)
        sys.exit(1)
    # create table for distribution version and codename mapping
    create_table_distribution_codename_version_mapping(CONFIG)

    print('[+] Updating debian vulnerability database')
    error = loop.run_until_complete(update_vuln_debian_db(CONFIG))
    if error:
        print(error)
        sys.exit(1)
    print('[+] Updating ubuntu vulnerability database')
    error = loop.run_until_complete(update_vuln_ubuntu_db(CONFIG))
    if error:
        print(error)
        sys.exit(1)
    print('[+] Updating redhat vulnerability database')
    error = loop.run_until_complete(update_vuln_redhat_db(CONFIG))
    if error:
        print(error)
        sys.exit(1)
    # remove backup file on success
    if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
        os.remove(CONFIG['DATABASE_BACKUP_FILE'])

    print('[+] Add new cpes to database')
    error = add_new_cpes_to_db(NEW_CPES_INFOS, CONFIG)
    if error:
        print('[-] Error adding new cpe information')
        sys.exit(1)


def quick_update(config_file):
    print("[+] Downloading latest versions of resources ...")

    if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
        shutil.move(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
    if os.path.isfile(CONFIG['cpe_search']['DEPRECATED_CPES_FILE']):
        shutil.move(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'], CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
    if os.path.isfile(CONFIG['DATABASE_NAME']):
        shutil.move(CONFIG['DATABASE_NAME'], CONFIG['DATABASE_BACKUP_FILE'])
    # backup databases
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
        backup_mariadb(config_file)

    try:
        quiet_flag = ""
        if QUIET:
            quiet_flag = "-q"
        else:
            quiet_flag = "-q --show-progress"
        return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(CPE_DICT_ARTIFACT_URL),
                                        shlex.quote(CONFIG['cpe_search']['DATABASE_NAME'])), shell=True)
        if return_code != 0:
            raise(Exception("Could not download latest resource files"))

        return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(CPE_DEPRECATIONS_ARTIFACT_URL),
                                        shlex.quote(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])), shell=True)
        if return_code != 0:
            raise(Exception("Could not download latest resource files"))

        return_code = subprocess.call("wget %s %s -O %s" % (quiet_flag, shlex.quote(VULNDB_ARTIFACT_URL),
                                        shlex.quote(CONFIG['DATABASE_NAME'])), shell=True)
        if return_code != 0:
            raise(Exception("Could not download latest resource files"))

        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            os.remove(CONFIG['CPE_DATABASE_BACKUP_FILE'])
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            os.remove(CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
        if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
            os.remove(CONFIG['DATABASE_BACKUP_FILE'])

    except Exception as e:
        print("[!] Encountered an error: %s" % str(e))
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            shutil.move(CONFIG['CPE_DATABASE_BACKUP_FILE'], CONFIG['cpe_search']['DATABASE_NAME'])
            print("[+] Restored software infos from backup")
        if os.path.isfile(CONFIG['DEPRECATED_CPES_BACKUP_FILE']):
            shutil.move(CONFIG['DEPRECATED_CPES_BACKUP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE'])
            print("[+] Restored software deprecation infos from backup")
        if os.path.isfile(CONFIG['DATABASE_BACKUP_FILE']):
            shutil.move(CONFIG['DATABASE_BACKUP_FILE'], CONFIG['DATABASE_NAME'])
            print("[+] Restored vulnerability infos from backup")

    # migrate SQLite to MariaDB if specified database type is mariadb
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
        migrate_to_mariadb(config_file) 


def run(full=False, nvd_api_key=None, config_file=''):
    global CONFIG
    config_file = os.path.join(os.path.dirname(os.path.abspath(config_file)), config_file)

    # load config
    if config_file:
        CONFIG = _load_config(config_file)
    else:
        CONFIG = _load_config()
    CONFIG = update_config_generic()

    # create file dirs as needed
    update_files = [CONFIG['CVE_EDB_MAP_FILE'], CONFIG['cpe_search']['DEPRECATED_CPES_FILE'],
                    CONFIG['MAN_EQUIVALENT_CPES_FILE']]
    if CONFIG['DATABASE']['TYPE'] == 'sqlite':
        update_files += [CONFIG['DATABASE_NAME'], CONFIG['cpe_search']['DATABASE_NAME']]
    for file in update_files:
        os.makedirs(os.path.dirname(file), exist_ok=True)

    if full:
        full_update(nvd_api_key, config_file) 
    else:
        quick_update(config_file)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--full':
        run(True)
    else:
        run(False)