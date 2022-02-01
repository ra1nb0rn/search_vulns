#!/usr/bin/env python3

import sqlite3
import os
from flask import Flask, request
from search_vulns import search_vulns as search_vulns_call

DATABASE_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulndb.db3')
DB_URI = 'file:vuln_db?mode=memory&cache=shared'


app = Flask(__name__)

@app.route("/search_vulns")
def search_vulns():
    query = request.args.get('query')
    conn = sqlite3.connect(DB_URI, uri=True)
    db_cursor = conn.cursor()
    vulns = search_vulns_call(query, db_cursor=db_cursor, keep_data_in_memory=True)
    if vulns is None:
        return {query: 'Warning: Could not find matching software for query \'%s\'' % query}
    else:
        return {query: vulns}

DB_CONN_FILE = sqlite3.connect(DATABASE_FILE)
DB_CONN_MEM = sqlite3.connect(DB_URI, uri=True)
DB_CONN_FILE.backup(DB_CONN_MEM)

# trigger putting of CPE data into memory with some query
conn = sqlite3.connect(DB_URI, uri=True)
db_cursor = conn.cursor()
search_vulns_call('Sudo 1.8.2', db_cursor=db_cursor, keep_data_in_memory=True)

if __name__ == '__main__':
    app.run()
