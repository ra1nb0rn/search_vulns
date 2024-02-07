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
    if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
        shutil.move(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
    if os.path.isfile(CONFIG['cpe_search']['DEPRECATED_CPES_FILE']):
        shutil.move(CONFIG['cpe_search']['DEPRECATED_CPES_FILE'], CONFIG['DEPRECATED_CPES_BACKUP_FILE'])
    if CONFIG['DATABASE']['TYPE'] == 'mariadb':
       backup_mariadb_database(CONFIG['cpe_search']['DATABASE_NAME'])

    success = await update_cpe(nvd_api_key, config['cpe_search'])
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

def add_new_cpes_to_db(new_cpes, config):
    # backup database
    if os.path.isfile(CONFIG['cpe_search']['DATABASE_NAME']):
        shutil.copy(CONFIG['cpe_search']['DATABASE_NAME'], CONFIG['CPE_DATABASE_BACKUP_FILE'])
    try:
        add_cpe_infos_to_db(new_cpes, config)
    except:
        if os.path.isfile(CONFIG['CPE_DATABASE_BACKUP_FILE']):
            shutil.move(CONFIG['CPE_DATABASE_BACKUP_FILE'], CONFIG['cpe_search']['DATABASE_NAME'])
        return True
    # remove database backup on success
    if os.path.isfile(config['CPE_DATABASE_BACKUP_FILE']):
        os.remove(config['CPE_DATABASE_BACKUP_FILE'])
    return False


def add_cpe_infos_to_db(new_cpes, config):
    '''Add all new cpes to the cpe-search database'''

    db_conn = get_database_connection(CONFIG['DATABASE'], CONFIG['cpe_search']['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    counter_cpe_entries = db_cursor.execute('SELECT COUNT(*) FROM cpe_entries').fetchone()[0]+1
    db_terms_to_entries = db_cursor.execute('SELECT * FROM terms_to_entries').fetchall()
    db_cursor.execute('DROP TABLE terms_to_entries;')
    db_cursor.execute('''CREATE TABLE terms_to_entries (
                            term TEXT PRIMARY KEY,
                            entry_ids TEXT NOT NULL
                      );''')
    
    new_cpes.sort(key=lambda cpe: cpe[0].split(':')[10])
    unique_cpes = []
    # remove duplicates
    for cpe_infos in new_cpes:
        if not cpe_infos in unique_cpes:
            unique_cpes.append(cpe_infos)
    new_cpes = unique_cpes

    all_cpes = set(get_all_cpes(False, config['cpe_search']))

    terms_to_entries = {}
    for term, entry_ids in db_terms_to_entries:
        terms_to_entries[term] = []
        for eid in entry_ids.split(','):
            if '-' in eid:
                eid = eid.split('-')
                terms_to_entries[term] += list(range(int(eid[0]), int(eid[1])+1))
            else:
                terms_to_entries[term].append(int(eid))

    # add CPE infos to DB
    for cpe_info in new_cpes:
        if cpe_info[0] in all_cpes:       
            continue
        db_cursor.execute('INSERT INTO cpe_entries VALUES (?, ?, ?, ?)', (counter_cpe_entries, cpe_info[0], json.dumps(cpe_info[1]), cpe_info[2]))
        for term in cpe_info[1]:
            if term not in terms_to_entries:
                terms_to_entries[term] = []
            terms_to_entries[term].append(counter_cpe_entries)
        counter_cpe_entries += 1
    db_conn.commit()
    db_cursor.close()
    db_cursor = db_conn.cursor()

    # add term --> entries translations to DB
    for term, entry_ids in terms_to_entries.items():
        if not entry_ids:
            continue

        i = 0
        entry_ids_str = str(entry_ids[0])
        while i < len(entry_ids) - 1:
            start_i = i
            while (i < len(entry_ids) - 1) and entry_ids[i] + 1 == entry_ids[i+1]:
                i += 1
            if start_i == i:
                entry_ids_str += ',%d' % entry_ids[i]
            else:
                entry_ids_str += ',%d-%d' % (entry_ids[start_i], entry_ids[i])
            i += 1
        db_cursor.execute('INSERT INTO terms_to_entries VALUES (?, ?)', (term, entry_ids_str))

    db_conn.commit()
    db_cursor.close()
    db_conn.close()