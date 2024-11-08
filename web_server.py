#!/usr/bin/env python3

import datetime
import json
import markdown
import os
import requests
import sys
import time
import uuid

from flask import Flask, request
from flask import render_template, jsonify
from cpe_search.database_wrapper_functions import get_database_connection, get_connection_pools
from search_vulns import (
    _load_config,
    search_vulns as search_vulns_call,
    CPE_SEARCH_THRESHOLD_MATCH,
    MATCH_CPE_23_RE,
    VERSION_FILE
)
from cpe_search.cpe_search import search_cpes

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))
STATIC_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "static"))
TEMPLATE_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "templates"))
CONFIG_FILE = os.path.join(PROJECT_DIR, 'config.json')
CHANGELOG_FILE = os.path.join(PROJECT_DIR, 'CHANGELOG.md')
LICENSE_INFO_FILE = os.path.join(os.path.join(PROJECT_DIR, 'resources'), 'license_infos.md')
README_FILE = os.path.join(PROJECT_DIR, 'README.md')
CPE_SUGGESTIONS_COUNT = 10
MAX_QUERY_LENGTH = 256
VULN_RESULTS_CACHE, CPE_SUGGESTIONS_CACHE = {}, {}
RECAPTCHA_THRESHOLD = 0.7

app = Flask(__name__, static_folder=STATIC_FOLDER, template_folder=TEMPLATE_FOLDER)
config = _load_config(CONFIG_FILE)


def verify_recaptcha_response(secret_key, recaptcha_response):
    for _ in range(3):
        post_data = {'secret': secret_key, 'response': recaptcha_response}
        try:
            recaptcha_vrfy_response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=post_data)
            recaptcha_vrfy_response = recaptcha_vrfy_response.content.decode()
            recaptcha_vrfy_response = json.loads(recaptcha_vrfy_response)
            if 'score' in recaptcha_vrfy_response:  # reCAPTCHA v3
                if recaptcha_vrfy_response['score'] >= RECAPTCHA_THRESHOLD:
                    return True
                if recaptcha_vrfy_response['success']:
                    return False
            elif recaptcha_vrfy_response['success']:  # reCAPTCHA v2
                return True
        except:
            # catch any error and try again
            pass
        time.sleep(0.05)
    return False


def search_has_valid_auth(request):
    is_auth_request = False
    auth_error = None

    # check auth via API key
    api_key = request.headers.get('API-Key')
    if api_key:
        db_conn = get_database_connection(config['DATABASE'], config['RECAPTCHA_AND_API']['DATABASE_NAME'])
        db_cursor = db_conn.cursor()

        # first check if number of requests for key exceeds limit
        poll_time = datetime.datetime.now() - datetime.timedelta(seconds=config['RECAPTCHA_AND_API']['API_REQUESTS_RATE_LIMIT_WINDOW'])
        poll_time = poll_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        db_cursor.execute('SELECT COUNT(time) FROM recent_api_requests WHERE api_key = ? and time > ?', (api_key, poll_time))
        request_count = db_cursor.fetchall()
        if not request_count:
            auth_error = ('Could not get count of recent API requests for provided API key', 403)
        request_count = request_count[0]
        if not auth_error and not request_count:
            auth_error = ('Could not get count of recent API requests for provided API key', 403)
        request_count = request_count[0]
        if not auth_error and request_count + 1 > config['RECAPTCHA_AND_API']['API_REQUESTS_RATE_LIMIT_COUNT']:
            auth_error = ('Too many requests with this API key. Try again in a couple of minutes.', 403)

        # then insert the current request into the DB and issue valid auth response
        if not auth_error:
            success = False
            for _ in range(3):
                try:
                    datetime_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    db_cursor.execute('INSERT INTO recent_api_requests VALUES(?, ?)', (api_key, datetime_now))
                    success = True
                    break
                except Exception as e:
                    if 'integrity' in str(e).lower() or 'duplicate' in str(e).lower():
                        continue
                    else:
                        raise e
            db_conn.commit()
            db_cursor.close()
            db_conn.close()
            if not success:
                auth_error = ('Could not insert API request into DB due to an integrity error.', 500)
            is_auth_request = True

    # check auth via reCAPTCHA
    if not is_auth_request and 'Recaptcha-Response' in request.headers:
        secret_key = config["RECAPTCHA_AND_API"]["SECRET_KEY_V3"]
        recaptcha_respone = request.headers['Recaptcha-Response']
        is_auth_request = verify_recaptcha_response(secret_key, recaptcha_respone)
        if is_auth_request:
            auth_error = None
        elif not api_key:
            auth_error = 'Neither a valid API key nor a valid reCAPTCHA token was provided.', 403

    if not is_auth_request and auth_error is None:
        auth_error = 'Neither a valid API key nor a valid reCAPTCHA token was provided.', 403

    return is_auth_request, auth_error


@app.route("/api/cpe-suggestions")
def cpe_suggestions():
    # check auth if CAPTCHA or API key is required
    if config['RECAPTCHA_AND_API']['ENABLED']:
        has_valid_auth, auth_error = search_has_valid_auth(request)
        if not has_valid_auth:
            return auth_error

    query = request.args.get('query')
    if not query:
        return "No query provided", 400
    query = query.strip()
    query_lower = query.lower()

    # limit query length in CAPTCHA / API scenario
    if config['RECAPTCHA_AND_API']['ENABLED'] and len(query) > MAX_QUERY_LENGTH:
        return f'Query length is limited to {MAX_QUERY_LENGTH} characters.', 413

    if MATCH_CPE_23_RE.match(query_lower):
        return [(query_lower, -1)]

    if query_lower in CPE_SUGGESTIONS_CACHE:
        return jsonify(CPE_SUGGESTIONS_CACHE[query_lower])

    cpe_suggestions = search_cpes(query, threshold=CPE_SEARCH_THRESHOLD_MATCH, count=CPE_SUGGESTIONS_COUNT, config=config['cpe_search'])
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


@app.route("/api/search-vulns")
def search_vulns():
    # check auth if CAPTCHA or API key is required
    if config['RECAPTCHA_AND_API']['ENABLED']:
        has_valid_auth, auth_error = search_has_valid_auth(request)
        if not has_valid_auth:
            return auth_error

    url_query_string = request.query_string.lower()
    query = request.args.get('query')
    if not query:
        return "No query provided", 400
    query = query.strip()
    is_vuln_ids_query = query.startswith('CVE-') or query.startswith('GHSA-')

    # limit query length in CAPTCHA / API scenario
    if config['RECAPTCHA_AND_API']['ENABLED'] and len(query) > MAX_QUERY_LENGTH:
        return f'Query length is limited to {MAX_QUERY_LENGTH} characters.', 413

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

    if cpe_suggestions and not is_vuln_ids_query:
        query_cpe = cpe_suggestions[0][0]
        is_good_cpe = False  # query was never issued as CPE --> use CPE deprecations and equivalences
        vulns = search_vulns_call(query_cpe, db_cursor=db_cursor, add_other_exploit_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, is_good_cpe=is_good_cpe, config=config)
        vulns = {query: vulns[query_cpe]}
        vulns[query]['pot_cpes'] = cpe_suggestions
    else:
        vulns = search_vulns_call(query, db_cursor=db_cursor, add_other_exploit_refs=True, ignore_general_cpe_vulns=ignore_general_cpe_vulns, include_single_version_vulns=include_single_version_vulns, is_good_cpe=is_good_cpe, config=config)
        query_lower = query.lower()
        if (not is_vuln_ids_query) and (not MATCH_CPE_23_RE.match(query_lower)):
            CPE_SUGGESTIONS_CACHE[query_lower] = vulns[query]['pot_cpes']

    db_cursor.close()
    db_conn.close()

    if vulns is None:
        vulns = {}

    # do not cache vuln IDs search
    if not is_vuln_ids_query:
        VULN_RESULTS_CACHE[url_query_string] = vulns

    return vulns


@app.route("/api/version")
def version():
    with open(VERSION_FILE) as f:
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
    show_captcha = config['RECAPTCHA_AND_API']['ENABLED']
    if request.cookies.get('isAPIKeyConfigured', '').lower() == 'true':
        show_captcha = False

    recaptcha_settings = {'recaptcha_site_key': config['RECAPTCHA_AND_API']['SITE_KEY_V3'],
                          'show_captcha': show_captcha}
    return render_template("index.html", **recaptcha_settings)


def style_converted_html(markdown_html, center_captions=False):
    ctr_str = 'text-center ' if center_captions else ''
    markdown_html = markdown_html.replace('<h1>', f'<h1 class="{ctr_str}text-2xl my-3 font-bold">')
    markdown_html = markdown_html.replace('<h2>', f'<h2 class="{ctr_str}text-xl mt-3 mb-1 font-semibold">')
    markdown_html = markdown_html.replace('<h3>', f'<h3 class="{ctr_str}text-lg my-1 font-medium">')
    markdown_html = markdown_html.replace('<ul>', '<ul class="list-disc text-left ml-6 mb-3 mt-1">')
    markdown_html = markdown_html.replace('<code>', '<code class="bg-base-300 p-1 rounded-lg">')
    markdown_html = markdown_html.replace('<p>', '<p class="mt-2">')
    markdown_html = markdown_html.replace('<a ', '<a class="link" ')
    return markdown_html


@app.route("/about")
def about():
    markdown_content = ''
    with open(README_FILE) as f:
        markdown_content = f.read()

    markdown_content = markdown_content[markdown_content.find('## About'):]
    markdown_content = markdown_content[:markdown_content.find('\n##')]
    about_html = style_converted_html(markdown.markdown(markdown_content), True)

    markdown_content = ''
    with open(LICENSE_INFO_FILE) as f:
        markdown_content = f.read()
    license_html = style_converted_html(markdown.markdown(markdown_content), True)

    return render_template("about.html", about_html=about_html, license_html=license_html)


@app.route("/api/setup")
def api_setup():
    recaptcha_settings = {'recaptcha_site_key': config['RECAPTCHA_AND_API']['SITE_KEY_V2'],
                          'show_captcha': config['RECAPTCHA_AND_API']['ENABLED']}
    return render_template("api-setup.html", **recaptcha_settings)


@app.route("/api/generate-key", methods=['POST'])
def generate_api_key():
    # check reCAPTCHA
    if config['RECAPTCHA_AND_API']['ENABLED']:
        secret_key = config["RECAPTCHA_AND_API"]["SECRET_KEY_V2"]
        recaptcha_response = request.form.get('recaptcha_response')
        if not recaptcha_response:
            return {'status': 'error', 'msg': 'Provided ReCAPTCHA token was empty.'}
        recaptcha_is_valid = verify_recaptcha_response(secret_key, recaptcha_response)

        if not recaptcha_is_valid:
            return {'status': 'error', 'msg': 'ReCAPTCHA was invalid.'}

    # insert in DB and check that it's not duplicate
    db_conn = get_database_connection(config['DATABASE'], config['RECAPTCHA_AND_API']['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    api_key, success = str(uuid.uuid4()), False
    for _ in range(3):
        try:
            db_cursor.execute('INSERT INTO api_keys VALUES(?, ?, ?)', (api_key, 'valid', datetime.datetime.now()))
            success = True
            break
        except Exception as e:
            if 'integrity' in str(e).lower() or 'duplicate' in str(e).lower():
                api_key = str(uuid.uuid4())  # try new key
                continue
            else:
                raise e

    if not success:
        return {'status': 'error', 'msg': 'Could not create and insert a new API key into the DB'}

    db_conn.commit()
    db_cursor.close()
    db_conn.close()

    return {'status': 'success', 'key': api_key}


@app.route("/api/check-key-status", methods=['POST'])
def check_api_key_status():
    key = request.json.get('key')
    if not key:
        return {'status': 'No key was provided'}

    db_conn = get_database_connection(config['DATABASE'], config['RECAPTCHA_AND_API']['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    db_cursor.execute('SELECT status FROM api_keys WHERE api_key = ?', (key, ))
    result = db_cursor.fetchall()
    db_cursor.close()
    db_conn.close()

    if not result:
        return {'status': 'Key does not exist in DB'}
    else:
        return {'status': result[0][0]}


@app.route("/news")
def news():
    markdown_content = ''
    with open(CHANGELOG_FILE) as f:
        markdown_content = f.read()

    changelog_html = style_converted_html(markdown.markdown(markdown_content), False)
    changelog_html = changelog_html.replace('<h1 class="', '<h1 class="text-center ')
    return render_template("news.html", news_html=changelog_html)


def setup_api_db():
    db_type, db_name = config['DATABASE']['TYPE'], config['RECAPTCHA_AND_API']['DATABASE_NAME']
    if not all([c.isalnum() or c in ('-', '_', '.', '/') for c in (db_name)]):
        print('Potential malicious database name detected. Aborting creation of database.')
        return False

    # create DB or skip if exists
    db_exists = None
    if db_type == 'mariadb':
        import mariadb
        db_conn = get_database_connection(config['DATABASE'], '', use_pool=False)
        db_cursor = db_conn.cursor()
        try:
            db_cursor.execute(f'CREATE DATABASE {db_name};')
        except mariadb.ProgrammingError as e:
            if 'database exists' in str(e).lower():
                db_exists = True
            else:
                print(str(e))
                db_exists = False
    else:
        db_conn = get_database_connection(config['DATABASE'], db_name)
        db_cursor = db_conn.cursor()

    if db_exists is None:
        db_conn.commit()
    db_cursor.close()
    db_conn.close()

    if db_exists is not None and not db_exists:
        return False

    # create tables if DB was just created, ignore if tables exist
    db_conn, db_cursor = None, None
    try:
        db_conn = get_database_connection(config['DATABASE'], db_name, use_pool=False)
        db_cursor = db_conn.cursor()
    except Exception as e:
        if 'many connections' not in str(e):
            raise e
    if db_conn:
        try:
            db_cursor.execute('CREATE TABLE api_keys (api_key CHAR(36), status VARCHAR(64), last_used DATETIME(3), PRIMARY KEY (api_key));')
        except Exception as e:
            if not 'exist' in str(e) and 'many connections' not in str(e):
                raise e
        try:
            db_cursor.execute('CREATE TABLE recent_api_requests (api_key CHAR(36), time DATETIME(3), PRIMARY KEY (api_key, time));')
        except Exception as e:
            if not 'exist' in str(e) and 'many connections' not in str(e):
                raise e
        db_conn.commit()
        db_cursor.close()
        db_conn.close()
    else:
        return True

    # clear all entries from "recent_api_requests" table
    db_conn = get_database_connection(config['DATABASE'], db_name, use_pool=False)
    db_cursor = db_conn.cursor()
    try:  # might fail if another process just created the database and is in setup
        db_cursor.execute('DELETE FROM recent_api_requests')
    except Exception as e:
        if not 'exist' in str(e) and 'many connections' not in str(e):
            raise e

    db_conn.commit()
    db_cursor.close()
    db_conn.close()

    return True


if __name__ == '__main__':
    print('[+] Loading resources')

# init test call and set up DB
db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
db_cursor = db_conn.cursor()
search_vulns_call('Sudo 1.8.2', db_cursor=db_cursor, config=config)
db_cursor.close()
db_conn.close()

if config['RECAPTCHA_AND_API']['ENABLED']:
    setup_success = setup_api_db()
    if not setup_success:
        print('Error: API DB could not be created.')
        sys.exit(1)


if __name__ == '__main__':
    print('[+] Starting webserver')
    app.run()

    # close DB pools if any exist
    for pool in get_connection_pools().values():
        pool.close()
