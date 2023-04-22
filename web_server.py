#!/usr/bin/env python3

import sqlite3
import os
from flask import Flask, request
from flask import render_template

from search_vulns import search_vulns_return_cpe as search_vulns_call

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
STATIC_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "static"))
TEMPLATE_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "templates"))
DATABASE_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulndb.db3')
DB_URI = 'file:vuln_db?mode=memory&cache=shared'
RESULTS_CACHE = {}


app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=TEMPLATE_FOLDER)

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

    is_good_cpe = request.args.get('is-good-cpe')
    if is_good_cpe and is_good_cpe.lower() == 'false':
        is_good_cpe = False
    else:
        is_good_cpe = True

    conn = sqlite3.connect(DB_URI, uri=True)
    db_cursor = conn.cursor()
    vulns = search_vulns_call(query, db_cursor=db_cursor, keep_data_in_memory=True, add_other_exploits_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, zero_extend_versions=True, is_good_cpe=is_good_cpe)

    if vulns is None:
        RESULTS_CACHE[url_query_string] = {}
        return {}
    else:
        RESULTS_CACHE[url_query_string] = vulns
        return vulns

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

if __name__ == '__main__':
    print('[+] Loading resources')

DB_CONN_FILE = sqlite3.connect(DATABASE_FILE)
DB_CONN_MEM = sqlite3.connect(DB_URI, uri=True)
DB_CONN_FILE.backup(DB_CONN_MEM)
DB_CONN_FILE.close()

# trigger putting of CPE data into memory with some query
conn = sqlite3.connect(DB_URI, uri=True)
db_cursor = conn.cursor()
search_vulns_call('Sudo 1.8.2', db_cursor=db_cursor, keep_data_in_memory=True)

if __name__ == '__main__':
    print('[+] Starting webserver')
    app.run()
