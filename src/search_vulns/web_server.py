#!/usr/bin/env python3

import datetime
import json
import os
import re
import sys
import time
import uuid

import markdown
import requests
from apiflask import APIBlueprint, APIFlask, abort
from cpe_search.database_wrapper_functions import (
    get_connection_pools,
)
from flask import jsonify, render_template, request, send_from_directory

from .core import (
    PROJECT_DIR,
    _load_config,
    check_and_try_sv_rerun_with_created_cpes,
    get_version,
    search_product_ids,
)
from .core import search_vulns as search_vulns_call
from .models.SearchVulnsResult import SearchVulnsResult
from .modules.utils import get_database_connection
from .web_server_files.api_models import *

STATIC_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "static"))
TEMPLATE_FOLDER = os.path.join(PROJECT_DIR, os.path.join("web_server_files", "templates"))
CONFIG_FILE = os.path.join(PROJECT_DIR, "config.json")
CHANGELOG_FILE = os.path.join(PROJECT_DIR, "CHANGELOG.md")
LICENSE_INFO_FILE = os.path.join(os.path.join(PROJECT_DIR, "resources"), "license_infos.md")
README_FILE = os.path.join(PROJECT_DIR, "README.md")
MAX_QUERY_LENGTH = 256
VULN_RESULTS_CACHE, PRODUCTID_SEARCH_CACHE = {}, {}
RECAPTCHA_THRESHOLD = 0.7
CODE_HIGHLIGHT_DETAILS_RE = re.compile(
    r'<code class="language-(\w+)"[^>]*?(hl_lines="([^"]*)")?>'
)
MD_TO_HTML_IMG_REPLACE_RE = re.compile(r'<img[^>]*src="(([^"]+\/)?([^"]+))"')
MD_TO_HTML_A_REPLACE_RE = re.compile(
    r'((<a[^>]*class=")([^"]*)("[^>]*>)(.*?)(?=<\/a>)<\/a>|(<a[^>]*>)(.*?)(?=<\/a>)<\/a>)'
)
MD_TO_HTML_H_ANCHOR_RE = re.compile(r"((<h\d[^>]*)(>([^<]*)<\/h\d>))")
MD_TO_HTML_TABLE_RE = re.compile(r"(<table[^>]*>.*?<\/table>)", re.DOTALL)
SEARCH_VULNS_VERSION = get_version()


app = APIFlask(
    __name__,
    title="search_vulns API",
    version=SearchVulnsResult().schema_version,
    static_folder=STATIC_FOLDER,
    template_folder=TEMPLATE_FOLDER,
    docs_path="/api/docs",
    spec_path="/api/openapi.json",
)
app.security_schemes = {
    "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "API-Key",
    }
}
api = APIBlueprint(
    "Public API",
    __name__,
    url_prefix="/api",
)
web = APIBlueprint("web", __name__, url_prefix="/", enable_openapi=False)
config = _load_config(CONFIG_FILE)
RECAPTCHA_DB_CONFIG = config["DATABASE_CONNECTION"]
RECAPTCHA_DB_CONFIG["NAME"] = config["RECAPTCHA_AND_API"]["DATABASE_NAME"]


def verify_recaptcha_response(secret_key, recaptcha_response):
    for _ in range(3):
        post_data = {"secret": secret_key, "response": recaptcha_response}
        try:
            recaptcha_vrfy_response = requests.post(
                "https://www.google.com/recaptcha/api/siteverify", data=post_data
            )
            recaptcha_vrfy_response = recaptcha_vrfy_response.content.decode()
            recaptcha_vrfy_response = json.loads(recaptcha_vrfy_response)
            if "score" in recaptcha_vrfy_response:  # reCAPTCHA v3
                if recaptcha_vrfy_response["score"] >= RECAPTCHA_THRESHOLD:
                    return True
                if recaptcha_vrfy_response["success"]:
                    return False
            elif recaptcha_vrfy_response["success"]:  # reCAPTCHA v2
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
    api_key = request.headers.get("API-Key")
    if api_key:
        db_conn = get_database_connection(RECAPTCHA_DB_CONFIG)
        db_cursor = db_conn.cursor()

        # first check if key is valid
        db_cursor.execute("SELECT api_key, status FROM api_keys WHERE api_key = ?", (api_key,))
        api_keys = db_cursor.fetchall()
        if not api_keys:
            auth_error = ("API key is unknown", 401)
            is_auth_request = False
        elif api_keys[0][1].lower() != "valid":
            auth_error = ("API key is invalid, key status: " + str(api_keys[0][1]), 401)
            is_auth_request = False

        # then check if number of requests for key exceeds limit
        if not auth_error:
            poll_time = datetime.datetime.now() - datetime.timedelta(
                seconds=config["RECAPTCHA_AND_API"]["API_REQUESTS_RATE_LIMIT_WINDOW"]
            )
            poll_time = poll_time.strftime("%Y-%m-%d %H:%M:%S.%f")

            db_cursor.execute(
                "SELECT COUNT(time) FROM recent_api_requests WHERE api_key = ? and time > ?",
                (api_key, poll_time),
            )
            request_count = db_cursor.fetchall()
            if not request_count:
                auth_error = (
                    "Could not get count of recent API requests for provided API key",
                    500,
                )
            request_count = request_count[0]
            if not auth_error and not request_count:
                auth_error = (
                    "Could not get count of recent API requests for provided API key",
                    500,
                )
            request_count = request_count[0]
            if (
                not auth_error
                and request_count + 1
                > config["RECAPTCHA_AND_API"]["API_REQUESTS_RATE_LIMIT_COUNT"]
            ):
                auth_error = (
                    "Too many requests with this API key. Try again in a couple of minutes.",
                    429,
                )

            # then insert the current request into the DB and issue valid auth response
            if not auth_error:
                success = False
                for _ in range(3):
                    try:
                        datetime_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                        db_cursor.execute(
                            "INSERT INTO recent_api_requests VALUES(?, ?)",
                            (api_key, datetime_now),
                        )
                        success = True
                        break
                    except Exception as e:
                        if "integrity" in str(e).lower() or "duplicate" in str(e).lower():
                            continue
                        else:
                            raise e
                db_conn.commit()
                if not success:
                    auth_error = (
                        "Could not insert API request into DB due to an integrity error.",
                        500,
                    )
                is_auth_request = True

        # close DB resources either way
        db_cursor.close()
        db_conn.close()

    # check auth via reCAPTCHA
    if not is_auth_request and "Recaptcha-Response" in request.headers:
        secret_key = config["RECAPTCHA_AND_API"]["SECRET_KEY_V3"]
        recaptcha_respone = request.headers["Recaptcha-Response"]
        is_auth_request = verify_recaptcha_response(secret_key, recaptcha_respone)
        if is_auth_request:
            auth_error = None
        elif not api_key:
            auth_error = (
                "Neither a valid API key nor a valid reCAPTCHA token was provided.",
                401,
            )

    if not is_auth_request and auth_error is None:
        auth_error = "Neither a valid API key nor a valid reCAPTCHA token was provided.", 401

    return is_auth_request, auth_error


@api.route("/product-id-suggestions")
@api.doc(
    summary="Retrieve Product IDs",
    description="Retrieve product IDs and suggestions that match the queried product.",
    security="ApiKeyAuth",
    responses={429: "Too Many Requests"},
)
@api.input(ProductIDQuery, location="query")
@api.output(SearchVulnsResult)
def product_id_suggestions(query_data):
    # check auth if CAPTCHA or API key is required
    if config["RECAPTCHA_AND_API"]["ENABLED"]:
        has_valid_auth, auth_error = search_has_valid_auth(request)
        if not has_valid_auth:
            abort(auth_error[1], auth_error[0])

    query = query_data.query
    if not query:
        abort(400, "No query provided")
    query = query.strip()
    query_lower = query.lower()

    # limit query length in CAPTCHA / API scenario
    if config["RECAPTCHA_AND_API"]["ENABLED"] and len(query) > MAX_QUERY_LENGTH:
        abort(413, f"Query length is limited to {MAX_QUERY_LENGTH} characters.")

    # try to retrieve results from cache and return early
    if (
        query_lower in PRODUCTID_SEARCH_CACHE
        and PRODUCTID_SEARCH_CACHE[query_lower].product_ids
    ):
        return jsonify(PRODUCTID_SEARCH_CACHE[query_lower].model_dump(exclude_none=True))

    product_ids, productid_suggestions = search_product_ids(query, None, False, config, {})

    result = SearchVulnsResult()
    result.product_ids = product_ids
    result.pot_product_ids = productid_suggestions
    PRODUCTID_SEARCH_CACHE[query_lower] = result

    return jsonify(result.model_dump(exclude_none=True))


@api.route("/search-vulns")
@api.doc(
    summary="Search for known vulnerabilities, exploits and more",
    description="Search for known vulnerabilities, exploits and more by using search_vulns' core engine and its modules.",
    security="ApiKeyAuth",
    responses={429: "Too Many Requests"},
)
@app.input(SearchVulnsQuery, location="query")
@app.output(SearchVulnsResult)
def search_vulns(query_data: SearchVulnsQuery):
    # check auth if CAPTCHA or API key is required
    if config["RECAPTCHA_AND_API"]["ENABLED"]:
        has_valid_auth, auth_error = search_has_valid_auth(request)
        if not has_valid_auth:
            abort(auth_error[1], auth_error[0])

    url_query_string = request.query_string.lower()
    query = query_data.query
    if not query:
        abort(400, "No query provided")
    query = query.strip()

    # limit query length in CAPTCHA / API scenario
    if config["RECAPTCHA_AND_API"]["ENABLED"] and len(query) > MAX_QUERY_LENGTH:
        abort(413, f"Query length is limited to {MAX_QUERY_LENGTH} characters.")

    if url_query_string in VULN_RESULTS_CACHE:
        return jsonify(VULN_RESULTS_CACHE[url_query_string].model_dump(exclude_none=True))

    # set up retrieval preferences
    is_good_product_id = True if query_data.is_good_product_id == "true" else False
    ignore_general_product_vulns = (
        True if query_data.ignore_general_product_vulns == "true" else False
    )
    include_single_version_vulns = (
        True if query_data.include_single_version_vulns == "true" else False
    )
    include_patched = True if query_data.include_patched == "true" else False
    use_created_product_ids = True if query_data.use_created_product_ids == "true" else False

    # search for vulns either via previous cpe_search results or user's query
    productids = PRODUCTID_SEARCH_CACHE.get(query.lower(), SearchVulnsResult()).product_ids
    vulns = search_vulns_call(
        query,
        productids,
        None,
        None,
        is_good_product_id,
        ignore_general_product_vulns,
        include_single_version_vulns,
        include_patched,
        config,
    )
    query_lower = query.lower()
    product_id_cache_result = SearchVulnsResult()
    product_id_cache_result.product_ids = vulns.product_ids
    product_id_cache_result.pot_product_ids = vulns.pot_product_ids
    PRODUCTID_SEARCH_CACHE[query_lower] = product_id_cache_result

    if use_created_product_ids:
        _, vulns = check_and_try_sv_rerun_with_created_cpes(
            query,
            vulns,
            ignore_general_product_vulns,
            include_single_version_vulns,
            include_patched,
            use_created_product_ids,
            config,
        )

    VULN_RESULTS_CACHE[url_query_string] = vulns

    # serialize result for response
    return jsonify(vulns.model_dump(exclude_none=True))


@api.route("/version")
@app.output(SoftwareVersionResult)
@api.doc(
    summary="Retrieve search_vulns version information",
    description="Retrieve the version of search_vulns and datetime of the latest DB update.",
)
def version():
    db_conn = get_database_connection(config["VULN_DATABASE"])
    db_cursor = db_conn.cursor()
    db_cursor.execute("SELECT UTCTimestamp FROM meta_last_data_update;")
    last_update_utc = db_cursor.fetchall()[0][0]
    if isinstance(last_update_utc, str):  # (sqlite)
        last_update_utc = datetime.datetime.fromisoformat(last_update_utc)
        last_update_utc = last_update_utc.replace(tzinfo=datetime.timezone.utc)
    db_cursor.close()
    db_conn.close()

    result = SoftwareVersionResult(
        version=SEARCH_VULNS_VERSION,
        last_db_update_ts=last_update_utc.timestamp(),
        last_db_update=last_update_utc.strftime("%a, %d %b %Y %H:%M:%S UTC"),
    )
    return result


@web.route("/")
@web.route("/index")
@web.route("/home")
def index():
    show_captcha = config["RECAPTCHA_AND_API"]["ENABLED"]
    if request.cookies.get("isAPIKeyConfigured", "").lower() == "true":
        show_captcha = False

    recaptcha_settings = {
        "recaptcha_site_key": config["RECAPTCHA_AND_API"]["SITE_KEY_V3"],
        "show_captcha": show_captcha,
    }
    return render_template("index.html", sv_version=SEARCH_VULNS_VERSION, **recaptcha_settings)


def style_md_converted_html(markdown_html, center_captions=False, with_color=False):
    ctr_str = "text-center " if center_captions else ""
    h_color_str = " text-primary" if with_color else ""
    a_color_str = " link-accent" if with_color else ""
    markdown_html = markdown_html.replace(
        "<h1>", f'<h1 class="{ctr_str}text-2xl my-3 font-bold{h_color_str} h1-content">'
    )
    markdown_html = markdown_html.replace(
        "<h2>", f'<h2 class="{ctr_str}text-xl mt-4 font-semibold{h_color_str} h2-content">'
    )
    markdown_html = markdown_html.replace(
        "<h3>", f'<h3 class="{ctr_str}text-lg mt-3 font-medium{h_color_str} h3-content">'
    )
    markdown_html = markdown_html.replace(
        "<h4>", f'<h4 class="{ctr_str}text-base-lg mt-3 font-medium{h_color_str} h4-content">'
    )
    markdown_html = markdown_html.replace(
        "<ul>", '<ul class="list-disc text-left ml-7 mb-3 mt-1 ul-content">'
    )
    markdown_html = markdown_html.replace(
        "<ol>", '<ol class="list-decimal text-left ml-7 mb-3 mt-1 ol-content">'
    )
    markdown_html = markdown_html.replace(
        "<pre><code>",
        '<pre class="pre-content" style="display: grid !important; grid-template-columns: repeat(1, minmax(0, 1fr)) !important; overflow-x: auto !important;"><code class="bg-base-300 p-2 rounded-lg code-content">',
    )
    markdown_html = markdown_html.replace(
        "<code>", '<code class="bg-base-300 p-1 rounded-lg dont-break-out code-content">'
    )
    markdown_html = markdown_html.replace("<p>", '<p class="mb-3 p-content">')
    markdown_html = markdown_html.replace(
        "<table>",
        '<table class="table table-mdsm sv-vuln-table-zebra table-rounded table-auto mb-3 table-content">',
    )
    markdown_html = markdown_html.replace("<th ", '<th class="bg-base-300 th-content" ')
    markdown_html = markdown_html.replace("<th>", '<th class="bg-base-300 th-content">')
    if "<a" in markdown_html:
        for a in MD_TO_HTML_A_REPLACE_RE.findall(markdown_html):
            if a[2]:
                new_a = a[1] + a[2] + " link" + a_color_str
                if "//" in a[4] or "?" in a[4]:
                    new_a += " dont-break-out a-content"
                new_a += a[3] + a[4] + "</a>"
            else:
                new_a = a[5][:-1] + " " + 'class="link' + a_color_str
                if "//" in a[6] or "?" in a[6]:
                    new_a += " dont-break-out a-content"
                new_a += '">' + a[6].replace('.', '.<wbr>') + "</a>"
            markdown_html = markdown_html.replace(a[0], new_a)
    if "<h" in markdown_html:
        for header in MD_TO_HTML_H_ANCHOR_RE.findall(markdown_html):
            anchor = header[3]
            anchor = anchor.replace("&amp;", "&")
            anchor = re.sub(r"[^\w _-]", "", anchor)
            anchor = anchor.lower()
            anchor = anchor.replace(" ", "-")
            new_tag = header[1] + ' id="' + anchor + '"' + header[2]
            markdown_html = markdown_html.replace(header[0], new_tag)
    if "<table" in markdown_html:
        for table in MD_TO_HTML_TABLE_RE.findall(markdown_html):
            new_table_str = "<div>" + table + "</div>"
            markdown_html = markdown_html.replace(table, new_table_str)

    return markdown_html


@web.route("/about")
def about():
    readme_markdown_content = ""
    with open(README_FILE) as f:
        readme_markdown_content = f.read()

    markdown_content = readme_markdown_content[readme_markdown_content.find("## About") :]
    markdown_content = markdown_content[: markdown_content.find("\n##")]
    about_html = style_md_converted_html(
        markdown.markdown(markdown_content, extensions=["tables"]), True, True
    )

    markdown_content = readme_markdown_content[readme_markdown_content.find("## Modules") :]
    markdown_content = markdown_content[: markdown_content.find("\n##")]
    modules_html = style_md_converted_html(
        markdown.markdown(markdown_content, extensions=["tables"]), True, True
    )

    markdown_content = ""
    with open(LICENSE_INFO_FILE) as f:
        markdown_content = f.read()
    license_html = style_md_converted_html(
        markdown.markdown(markdown_content, extensions=["tables"]), True, True
    )

    return render_template(
        "about.html",
        sv_version=SEARCH_VULNS_VERSION,
        about_html=about_html,
        modules_html=modules_html,
        license_html=license_html,
    )


@web.route("/api/setup")
def api_setup():
    recaptcha_settings = {
        "recaptcha_site_key": config["RECAPTCHA_AND_API"]["SITE_KEY_V2"],
        "show_captcha": config["RECAPTCHA_AND_API"]["ENABLED"],
    }
    return render_template(
        "api-setup.html", sv_version=SEARCH_VULNS_VERSION, **recaptcha_settings
    )


@web.route("/api/generate-key", methods=["POST"])
def generate_api_key():
    # check reCAPTCHA
    if config["RECAPTCHA_AND_API"]["ENABLED"]:
        secret_key = config["RECAPTCHA_AND_API"]["SECRET_KEY_V2"]
        recaptcha_response = request.form.get("recaptcha_response")
        if not recaptcha_response:
            return {"status": "error", "msg": "Provided ReCAPTCHA token was empty."}
        recaptcha_is_valid = verify_recaptcha_response(secret_key, recaptcha_response)

        if not recaptcha_is_valid:
            return {"status": "error", "msg": "ReCAPTCHA was invalid."}

    # insert in DB and check that it's not duplicate
    db_conn = get_database_connection(RECAPTCHA_DB_CONFIG)
    db_cursor = db_conn.cursor()
    api_key, success = str(uuid.uuid4()), False
    for _ in range(3):
        try:
            db_cursor.execute(
                "INSERT INTO api_keys VALUES(?, ?, ?)",
                (api_key, "valid", datetime.datetime.now()),
            )
            success = True
            break
        except Exception as e:
            if "integrity" in str(e).lower() or "duplicate" in str(e).lower():
                api_key = str(uuid.uuid4())  # try new key
                continue
            else:
                raise e

    if not success:
        return {
            "status": "error",
            "msg": "Could not create and insert a new API key into the DB",
        }

    db_conn.commit()
    db_cursor.close()
    db_conn.close()

    return {"status": "success", "key": api_key}


@api.route("/check-key-status", methods=["POST"])
@api.doc(summary="Check API key status", description="Check the status of your API key.")
@api.input(CheckKeyStatusIn)
@api.output(CheckKeyStatusResult)
def check_api_key_status(json_data):
    key = json_data.key
    if not key:
        return {"status": "No key was provided"}

    db_conn = get_database_connection(RECAPTCHA_DB_CONFIG)
    db_cursor = db_conn.cursor()
    db_cursor.execute("SELECT status FROM api_keys WHERE api_key = ?", (key,))
    result = db_cursor.fetchall()
    db_cursor.close()
    db_conn.close()

    if not result:
        return {"status": "Key does not exist in DB"}
    else:
        return {"status": result[0][0]}


@web.route("/api/documentation")
def api_documentation():
    return send_from_directory(STATIC_FOLDER, "search_vulns_openapi.yaml")


@web.route("/news")
def news():
    markdown_content = ""
    with open(CHANGELOG_FILE) as f:
        markdown_content = f.read()

    changelog_html = style_md_converted_html(
        markdown.markdown(markdown_content, extensions=["tables"]), False, True
    )
    changelog_html = changelog_html.replace('<h1 class="', '<h1 class="text-center ')
    return render_template(
        "news.html", sv_version=SEARCH_VULNS_VERSION, news_html=changelog_html
    )


def setup_api_db():
    db_type, db_name = RECAPTCHA_DB_CONFIG["TYPE"], RECAPTCHA_DB_CONFIG["NAME"]
    if not all([c.isalnum() or c in ("-", "_", ".", "/") for c in (db_name)]):
        print("Potential malicious database name detected. Aborting creation of database.")
        return False

    # create DB or skip if exists
    db_exists = None
    if db_type == "mariadb":
        import mariadb

        db_conn = get_database_connection(RECAPTCHA_DB_CONFIG, "", use_pool=False)
        db_cursor = db_conn.cursor()
        try:
            db_cursor.execute(f"CREATE DATABASE {db_name};")
        except mariadb.ProgrammingError as e:
            if "database exists" in str(e).lower():
                db_exists = True
            else:
                print(str(e))
                db_exists = False
    else:
        db_conn = get_database_connection(RECAPTCHA_DB_CONFIG)
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
        db_conn = get_database_connection(RECAPTCHA_DB_CONFIG, use_pool=False)
        db_cursor = db_conn.cursor()
    except Exception as e:
        if "many connections" not in str(e):
            raise e
    if db_conn:
        try:
            db_cursor.execute(
                "CREATE TABLE api_keys (api_key CHAR(36), status VARCHAR(64), last_used DATETIME(3), PRIMARY KEY (api_key));"
            )
        except Exception as e:
            if "exist" not in str(e) and "many connections" not in str(e):
                raise e
        try:
            db_cursor.execute(
                "CREATE TABLE recent_api_requests (api_key CHAR(36), time DATETIME(3), PRIMARY KEY (api_key, time));"
            )
        except Exception as e:
            if "exist" not in str(e) and "many connections" not in str(e):
                raise e
        db_conn.commit()
        db_cursor.close()
        db_conn.close()
    else:
        return True

    # clear all entries from "recent_api_requests" table
    db_conn = get_database_connection(RECAPTCHA_DB_CONFIG, use_pool=False)
    db_cursor = db_conn.cursor()
    try:  # might fail if another process just created the database and is in setup
        db_cursor.execute("DELETE FROM recent_api_requests")
    except Exception as e:
        if "exist" not in str(e) and "many connections" not in str(e):
            raise e

    db_conn.commit()
    db_cursor.close()
    db_conn.close()

    return True


if __name__ == "__main__":
    print("[+] Loading resources")

# register up Web and API blueprints
app.register_blueprint(web)
app.register_blueprint(api)

# set up app info
app.info = {
    "description": 'Welcome to the official public instance of the search_vulns API!<br>This API allows you to search for vulnerabilities, exploits, product IDs and more.<br>An API key is required to use the API. It can be set up at <a href="/api/setup">/api/setup</a>.',
    "contact": {
        "name": "search_vulns Support",
        "url": "https://github.com/ra1nb0rn/search_vulns/issues",
    },
    "license": {
        "name": "MIT",
        "url": "https://github.com/ra1nb0rn/search_vulns/blob/master/LICENSE",
    },
}


# init test call
search_vulns_call("Sudo 1.8.2", config=config)

if config["RECAPTCHA_AND_API"]["ENABLED"]:
    setup_success = setup_api_db()
    if not setup_success:
        print("Error: API DB could not be created.")
        sys.exit(1)


if __name__ == "__main__":
    print("[+] Starting webserver")
    app.run()

    # close DB pools if any exist
    for pool in get_connection_pools().values():
        pool.close()
