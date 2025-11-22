# search_vulns
Search for known vulnerabilities in software using software titles or a CPE 2.3 string.

## About
*search_vulns* can be used to search for known vulnerabilities in software. To achieve this, the tool utilizes a locally built vulnerability database, currently containing:

* CVE information from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* Enhanced NVD information from [VulnCheck NVD++](https://vulncheck.com/nvd2)
* Exploit information from the [Exploit-DB (EDB)](https://www.exploit-db.com/)
* Exploit information from [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* Vulnerability information from the [GitHub Security Advisory Database](https://github.com/github/advisory-database)
* Software currency information from [endoflife.date](https://github.com/endoflife-date/endoflife.date)
* Backpatch information from the [Debian Security Bug Tracker](https://security-tracker.debian.org/tracker/)

Since search_vulns is designed in a modular fashion, new data sources and extensions can be integrated easily.

Using the *search_vulns* tool, this local information can be queried, either by providing software titles like 'Apache 2.4.39' or by providing a CPE 2.3 string like ``cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*``. You can also search for vulnerabilities like ``CVE-2023-1234`` or ``GHSA-xx68-jfcg-xmmf`` directly by using a comma-separated list of IDs.

*search_vulns* can either be used as a CLI tool or via a web server. It is recommended to use the CLI tool for automated workflows that might be resource-constrained. Otherwise, using the web server is recommended, because it offers more features and flexibility. This includes the ability to achieve more complete results. Also, the presentation of results is clearer and results can be exported for further use.


## Quick Links
* Public instance of the web server: [https://search-vulns.com](https://search-vulns.com)
* [Black Hat Arsenal recorded demo](https://search-vulns.com/static/video/SearchVulnsBlackHatDemo.mp4)
* [The Surprising Complexity of Finding Known Vulnerabilities](https://search-vulns.com/blog-post/1) - A blog post detailing the challenges and motivations behind search_vulns.
* [search_vulns: Simplifying the Surprising Complexity of Finding Known Vulnerabilities](https://search-vulns.com/blog-post/2) - A blog post introducing search_vulns and describing its features.
* [search_vulns: A Deep Dive into its Technologies and Approaches](https://search-vulns.com/blog-post/3) - A blog post detailing how search_vulns works on a technical level, including its novel approaches.


## Installation
The core of *search_vulns* can be installed as a lightweight Python package, optionally with a web server component. An extended installation can be performed, which enables you to build the local databases yourself instead of pulling them from [the latest release on GitHub](https://github.com/ra1nb0rn/search_vulns/releases/latest) and to use MariaDB as database backend. As of now, there are no other functional differences.

### Lightweight Python Package Installation
You can install the search_vulns Python package from PyPI like so:
```shell
pip3 install search_vulns
```
Note that you may have to include ``--break-system-packages``, or use a virtualenv or [*pipx*](https://github.com/pypa/pipx).

To install the required packages for the optional web server component, you can run:
```shell
pip3 install search_vulns[web]
```

You can also clone this repository, build the Python package yourself and keep all data editable and in the cloned repository (beneficial for development purposes):
```shell
git clone https://github.com/ra1nb0rn/search_vulns
pip3 install -e .
```

After installing *search_vulns*, you need to pull the prebuilt database files from GitHub like so:
```shell
search_vulns -u
```

Lastly, you can run *search_vulns* or start the *search_vulns* web server if the web dependencies are installed:
```shell
$ search_vulns -q 'jquery 2.1.3'
$ python3 -m search_vulns.web_server
```

### Complete / Full Installation of search_vulns
You can perform a full installation like so (see notes above regarding `pip` installation):
```shell
pip3 install search_vulns
search_vulns --full-install
```
Note that this installs some required system packages, as specified in the ``install.sh`` files throughout the code.

Thereafter, you can download the database files from GitHub as shown above or build the databases yourself:
```shell
search_vulns --full-update
```
Note, however, that you should supply API keys via a config file, e.g. [`src/search_vulns/config.json`](https://github.com/ra1nb0rn/search_vulns/blob/master/src/search_vulns/config.json) or as environment variables. The API keys are free and you just need to register with the [NVD](https://nvd.nist.gov/developers/request-an-api-key) or [VulnCheck](https://www.vulncheck.com/), for example.

### Dockerfile
There's also a ``Dockerfile`` you can use:
```shell
docker build -t search_vulns .
docker run -p 127.0.0.1:5000:5000 -it search_vulns bash
```
The port forwarding is optional, in case you do not intend on using the web server component.


## Usage
*search_vulns*'s usage information is shown in the following:
```
usage: search_vulns [-h] [-u] [--full-update] [--full-install] [-a] [-f {json,txt}] [-o OUTPUT]
                    [-q QUERY] [-c CONFIG] [-V] [--cpe-search-threshold CPE_SEARCH_THRESHOLD]
                    [--ignore-general-product-vulns] [--include-single-version-vulns]
                    [--use-created-product-ids] [--include-patched]

Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)

options:
  -h, --help            show this help message and exit
  -u, --update          Download the latest version of the the local vulnerability and software database
  --full-update         Fully (re)build the local vulnerability and software database
  --full-install        Fully install search_vulns, including all dependencies (python packages, system
                        packages etc.)
  -a, --artifacts       Print JSON list of artifacts created during full update
  -f {json,txt}, --format {json,txt}
                        Output format, either 'txt' or 'json' (default: 'txt')
  -o OUTPUT, --output OUTPUT
                        File to write found vulnerabilities to
  -q QUERY, --query QUERY
                        A query, either software title like 'Apache 2.4.39' or a product ID string (e.g.
                        CPE 2.3)
  -c CONFIG, --config CONFIG
                        A config file to use (default: config.json)
  -V, --version         Print the version of search_vulns
  --cpe-search-threshold CPE_SEARCH_THRESHOLD
                        Similarity threshold used for retrieving a CPE via the cpe_search tool
  --ignore-general-product-vulns
                        Ignore vulnerabilities that only affect a general product (i.e. without version)
  --include-single-version-vulns
                        Include vulnerabilities that only affect one specific version of a product when
                        querying a lower version
  --use-created-product-ids
                        If no matching product ID exists in the software database, automatically use
                        matching ones created by search_vulns
  --include-patched     Include vulnerabilities reported as (back)patched, e.g. by Debian Security
                        Tracker, in results
```
Note that when querying software with ``-q`` you have to put the software information in quotes if it contains any spaces. Also, you can use ``-q`` multiple times to make multiple queries at once. For one, a query can be a software name / title like 'Apache 2.4.39' or 'Wordpress 5.7.2'. Furthermore, a query can also be a [CPE 2.3](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe) string.

Here are some examples:
* Query *Sudo 1.8.2* for known vulnerabilities:
  ```bash
  $ ./search_vulns.py -q 'Sudo 1.8.2'

  [+] Sudo 1.8.2 (cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*/cpe:2.3:a:todd_miller:sudo:1.8.2:*:*:*:*:*:*:*)
  CVE-2019-14287 (CVSSv3.1/8.8): In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.
  Exploits:  https://www.exploit-db.com/exploits/47502
             [...]
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2019-14287, 2019-10-17
  CVE-2017-1000368 (CVSSv3.0/8.2): Todd Miller's sudo version 1.8.20p1 and earlier is vulnerable to an input validation (embedded newlines) in the get_process_ttyname() function resulting in information disclosure and command execution.
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2017-1000368, 2017-06-05
  [...]
  ```
* Query *Moodle 3.4.0* for known vulnerabilities:
  ```bash
  $ ./search_vulns.py -q 'Moodle 3.4.0'

  [+] Moodle 3.4.0 (cpe:2.3:a:moodle:moodle:3.4.0:*:*:*:*:*:*:*)
  CVE-2018-14630 (CVSSv3.0/8.8): moodle before versions 3.5.2, 3.4.5, 3.3.8, 3.1.14 is vulnerable to an XML import of ddwtos could lead to intentional remote code execution. When importing legacy 'drag and drop into text' (ddwtos) type quiz questions, it was possible to inject and execute PHP code from within the imported questions, either intentionally or by importing questions from an untrusted source.
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2018-14630, 2018-09-17
  CVE-2018-1133 (CVSSv3.0/8.8): An issue was discovered in Moodle 3.x. A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.
  Exploits:  https://www.exploit-db.com/exploits/46551
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2018-1133, 2018-05-25
  [...]
  ```


## Modularity
search_vulns' search engine is designed in a modular manner. Therefore, new databases can be integrated easily. For example, modules can help in finding product IDs, vulnerabilities, extra information about vulnerabilities and extra information about the queried product. Examples of the latter two are CVSS scores or software recency information. Furthermore, modules can classify identified vulnerabilities as patched if they store and utilize special information related to the query, for example.

Have a look at the template module to get started writing your own modules: [``src/search_vulns/modules/template/search_vulns_template.py``](https://github.com/ra1nb0rn/search_vulns/blob/master/src/search_vulns/modules/template/search_vulns_template.py).


## Running a Web Server
It is also possible to run a web server that provides this tool's functionality to clients over the network. [``src/search_vulns/web_server.py``](https://github.com/ra1nb0rn/search_vulns/blob/master/src/search_vulns/web_server.py) contains a working example using Flask. Depending on your environment, you may want to modify the server IP and port at the end of this file. To run a simple Flask web server, just run:
```bash
python3 -m search_vulns.web_server
```
Furthermore, you can use ``gunicorn`` to make the web server more scalable; for example by running:
```bash
gunicorn --worker-class=gevent --worker-connections=50 --workers=3 --bind '0.0.0.0:8000' search_vulns.wsgi:app
```
You can read more about choosing good ``gunicorn`` settings for your system [here](https://medium.com/building-the-system/gunicorn-3-means-of-concurrency-efbb547674b7). Note, however, that this tool is quite CPU intensive, meaning that scalability is somewhat limited.

Finally, you can also use Nginx as a reverse proxy. A sample configuration file is provided in [``web_server_files/nginx.conf.sample``](https://github.com/ra1nb0rn/search_vulns/blob/master/web_server_files/nginx.conf.sample). Again, you may have to adjust this to your needs. When using Nginx, make sure you have the app running at the configured endpoint(s). For the sample configuration file, for example, you would have to run something similar to the following:
```bash
gunicorn --worker-class=gevent --worker-connections=50 --workers=3 --bind 'unix:/tmp/gunicorn.sock' search_vulns.wsgi:app
```


## MariaDB as Alternative Database Option
search_vulns can be configured to use *MariaDB* as an alternative to the preconfigured *SQLite* mechanism. A sample configuration file for MariaDB is provided in [``src/search_vulns/config_mariadb.json``](https://github.com/ra1nb0rn/search_vulns/blob/master/src/search_vulns/config_mariadb.json).

Make sure that you adjust the values for MariaDB in the configuration file to your MariaDB deployment (*user*, *password*, *host* and *port*).

To use MariaDB instead of *SQLite* for the webserver, simply change the ``CONFIG_FILE`` variable in ``web_server.py`` to your config file (e.g. ``src/search_vulns/config_mariadb.json``).

To improve the performance of search_vulns with MariaDB, it is recommend to add the following settings to your MariaDB configuration file (e.g. ``/etc/mysql/my.cnf``):
```
[mariadb]
query_cache_type = 1
query_cache_size = 192M
innodb_buffer_pool_size = 8G
thread_handling = pool-of-threads
```
``innodb_buffer_pool_size`` should be set to approximately 80% of available memory (see [MariaDB's official documentation](https://mariadb.com/kb/en/innodb-system-variables/#innodb_buffer_pool_size)).


## License
*search_vulns* is licensed under the MIT license, see [here](https://github.com/ra1nb0rn/search_vulns/blob/master/LICENSE).

View the licenses of the included data sources [here](https://github.com/ra1nb0rn/search_vulns/blob/master/src/search_vulns/resources/license_infos.md).
