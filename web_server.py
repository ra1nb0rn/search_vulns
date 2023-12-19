#!/usr/bin/env python3

import datetime
import os
from flask import Flask, request
from flask import render_template, jsonify
from cpe_search.database_wrapper_functions import get_database_connection, get_connection_pools
from search_vulns import (
    _load_config,
    search_vulns as search_vulns_call,
    CPE_SEARCH_THRESHOLD_MATCH,
    CPE_SEARCH_COUNT,
    MATCH_CPE_23_RE
)
from cpe_search.cpe_search import search_cpes

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
STATIC_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "static"))
TEMPLATE_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "templates"))
CONFIG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'config.json')
VULN_RESULTS_CACHE, CPE_SUGGESTIONS_CACHE = {}, {}

app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=TEMPLATE_FOLDER)
config = _load_config(CONFIG_FILE)


@app.route("/cpe_suggestions")
def cpe_suggestions():
    query = request.args.get('query')
    if not query:
        return "No query provided", 400
    query = query.strip()
    query_lower = query.lower()

    if MATCH_CPE_23_RE.match(query_lower):
        return [(query_lower, -1)]

    if query_lower in CPE_SUGGESTIONS_CACHE:
        return jsonify(CPE_SUGGESTIONS_CACHE[query_lower])

    cpe_suggestions = search_cpes(query, threshold=CPE_SEARCH_THRESHOLD_MATCH, count=CPE_SEARCH_COUNT, config=config['cpe_search'])
    cpe_suggestions = cpe_suggestions['pot_cpes']

    cpe_suggestions_serializable = []
    for suggestion in cpe_suggestions:
        cpe_suggestions_serializable.append([suggestion[0], suggestion[1]])

    if cpe_suggestions is None:
        CPE_SUGGESTIONS_CACHE[query_lower] = []
        return jsonify([])
    else:
        CPE_SUGGESTIONS_CACHE[query_lower] = cpe_suggestions
        return jsonify(cpe_suggestions)


@app.route("/search_vulns")
def search_vulns():
    url_query_string = request.query_string.lower()

    query = request.args.get('query')
    if not query:
        return "No query provided", 400
    query = query.strip()

    if url_query_string in VULN_RESULTS_CACHE:
        return VULN_RESULTS_CACHE[url_query_string]

    # set up retrieval settings
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

    # search for vulns either via previous cpe_search results or user's query
    cpe_suggestions = CPE_SUGGESTIONS_CACHE.get(query.lower(), [])
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    if cpe_suggestions:
        query_cpe = cpe_suggestions[0][0]
        is_good_cpe = False  # query was never issued as CPE --> use CPE deprecations and equivalences
        vulns,_ = search_vulns_call(query_cpe, db_cursor=db_cursor, add_other_exploit_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, is_good_cpe=is_good_cpe, config=config)
        vulns = {query: {'cpe': vulns[query_cpe]['cpe'], 'vulns': vulns[query_cpe]['vulns'], 'pot_cpes': cpe_suggestions}}
    else:
        vulns,_ = search_vulns_call(query, db_cursor=db_cursor, add_other_exploit_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, is_good_cpe=is_good_cpe, config=config)
        query_lower = query.lower()
        if not MATCH_CPE_23_RE.match(query_lower):
            CPE_SUGGESTIONS_CACHE[query_lower] = vulns[query]['pot_cpes']

    db_cursor.close()
    db_conn.close()

    if vulns is None:
        VULN_RESULTS_CACHE[url_query_string] = {}
        return {}
    else:
        VULN_RESULTS_CACHE[url_query_string] = vulns
        return vulns


@app.route("/version")
def version():
    with open('version.txt') as f:
        search_vulns_version = f.read()

    db_modified_ts = os.path.getmtime(config['cpe_search']['DEPRECATED_CPES_FILE'])
    db_modified_datetime = datetime.datetime.fromtimestamp(db_modified_ts)

    result = {'version': search_vulns_version,
              'last_db_update_ts': db_modified_ts,
              'last_db_update': db_modified_datetime}

    return result


@app.route("/")
@app.route("/index")
@app.route("/home")
def index():
    return render_template("index.html")


@app.route("/usage")
def usage():
    return render_template("usage.html")


@app.route("/api-setup")
def api_setup():
    return render_template("api-setup.html")


@app.route("/news")
def news():
    return render_template("news.html")


if __name__ == '__main__':
    print('[+] Loading resources')


# init test call
db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
db_cursor = db_conn.cursor()
search_vulns_call('Sudo 1.8.2', db_cursor=db_cursor, config=config)
db_cursor.close()
db_conn.close()


if __name__ == '__main__':
    print('[+] Starting webserver')
    app.run()

    # close DB pools if any exist
    for pool in get_connection_pools().values():
        pool.close()
