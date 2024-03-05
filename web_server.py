#!/usr/bin/env python3

import datetime
import os
import sqlite3
try: # only use mariadb module if installed
    import mariadb
except:
    pass

from flask import Flask, request
from flask import render_template
from cpe_search.database_wrapper_functions import get_database_connection
from search_vulns import _load_config, search_vulns_return_cpe as search_vulns_call

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
STATIC_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "static"))
TEMPLATE_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "templates"))
CONFIG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config_mariadb.json')
DB_URI = 'file:vuln_db?mode=memory&cache=shared'
CONNECTION_POOL_SIZE = os.cpu_count() # should be equal to number of cpu cores? (https://dba.stackexchange.com/a/305726)
RESULTS_CACHE = {}


app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=TEMPLATE_FOLDER)
config = _load_config(CONFIG_FILE)

@app.route("/search_vulns")
def search_vulns():
    url_query_string = request.query_string.lower()

    if url_query_string in RESULTS_CACHE:
        return RESULTS_CACHE[url_query_string]

    query = request.args.get('query')
    if not query:
        return "No query provided", 400

    ignore_general_cpe_vulns = request.args.get('ignore-general-cpe-vulns')
    if ignore_general_cpe_vulns and ignore_general_cpe_vulns.lower() == 'true':
        ignore_general_cpe_vulns = True
    else:
        ignore_general_cpe_vulns = False

    include_single_version_vulns = request.args.get('include-single-version-vulns')
    if include_single_version_vulns and include_single_version_vulns.lower() == 'true':
        include_single_version_vulns = True
    else:
        include_single_version_vulns = False

    is_good_cpe = request.args.get('is-good-cpe')
    if is_good_cpe and is_good_cpe.lower() == 'false':
        is_good_cpe = False
    else:
        is_good_cpe = True

    if config['DATABASE']['TYPE'] == 'sqlite':
        conn = sqlite3.connect(DB_URI, uri=True)
    else:
        try:
            conn = pool.get_connection()
        except:
            conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = conn.cursor()
    vulns = search_vulns_call(query, db_cursor=db_cursor, keep_data_in_memory=True, add_other_exploits_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, is_good_cpe=is_good_cpe, config=config)
    db_cursor.close()
    conn.close()
    if vulns is None:
        RESULTS_CACHE[url_query_string] = {}
        return {}
    else:
        RESULTS_CACHE[url_query_string] = vulns
        return vulns


@app.route("/version")
def version():
    with open('version.txt') as f:
        search_vulns_version = f.read()

    db_modified_ts = os.path.getmtime(config['DATABASE_NAME'])
    db_modified_datetime = datetime.datetime.fromtimestamp(db_modified_ts)

    result = {'version': search_vulns_version,
              'last_db_update_ts': db_modified_ts,
              'last_db_update': db_modified_datetime}

    return result


@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")


if __name__ == '__main__':
    print('[+] Loading resources')

if config['DATABASE']['TYPE'] == 'sqlite':
    DB_CONN_FILE = sqlite3.connect(config['DATABASE_NAME'])
    DB_CONN_MEM = sqlite3.connect(DB_URI, uri=True)
    DB_CONN_FILE.backup(DB_CONN_MEM)
    DB_CONN_FILE.close()

    # trigger putting of CPE data into memory with some query
    conn = sqlite3.connect(DB_URI, uri=True)
else:
    conn_params = {
        'user': config['DATABASE']['USER'],
        'password': config['DATABASE']['PASSWORD'],
        'host': config['DATABASE']['HOST'],
        'port': config['DATABASE']['PORT'],
        'database': config['DATABASE_NAME']
    }
    pool= mariadb.ConnectionPool(pool_name="search_vulns_pool", pool_size=CONNECTION_POOL_SIZE, **conn_params)
    conn=pool.get_connection()
db_cursor = conn.cursor()
search_vulns_call('Sudo 1.8.2', db_cursor=db_cursor, keep_data_in_memory=True, config=config)
db_cursor.close()
conn.close()


if __name__ == '__main__':
    print('[+] Starting webserver')
    app.run()
    pool.close()
