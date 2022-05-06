# search_vulns
Search for known vulnerabilities in software using software titles or a CPE 2.3 string.

## About
*search_vulns* can be used to search for known vulnerabilities in software. To achieve this, the tool utilizes a locally built vulnerability database, currently containing CVE information from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) and exploit information from the [Exploit-DB (EDB)](https://www.exploit-db.com/). Using the *search_vulns* tool, this local information can be queried, either by providing software titles like 'Apache 2.4.39' or by providing a CPE 2.3 string like ``cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*``.

## Installation
To install this tool, simply run the ``install.sh`` script. First, this script automatically installs the required dependencies. Thereafter it downloads the required software and vulnerability resources (see the [Release artifacts](https://github.com/ra1nb0rn/search_vulns/releases/latest)). These resources can also be built directly by invoking the install script with the according flag: ``install.sh --full``. Note, however, that this may take more time than simply downloading the resources. Of course, you can also look at the installation script and setup everything manually. Finally, you can also use the provided ``Dockerfile`` to build a container:
```
docker build -t search_vulns .
```
and then start it:
```
docker run -it search_vulns
```

## Usage
*search_vulns*'s usage information is shown in the following:
```
usage: search_vulns.py [-h] [-u] [--full-update] [-f {txt,json}] [-o OUTPUT] [-q QUERY]

Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)

optional arguments:
  -h, --help            show this help message and exit
  -u, --update          Download the latest version of the the local vulnerability and software database
  --full-update         Build complete update of the local vulnerability and software database
  -f {txt,json}, --format {txt,json}
                        Output format, either 'txt' or 'json' (default: 'txt')
  -o OUTPUT, --output OUTPUT
                        File to write found vulnerabilities to
  -q QUERY, --query QUERY
                        A query, either software title like 'Apache 2.4.39' or a CPE 2.3 string
```
Note that when querying software with ``-q`` you have to put the software information in quotes if it contains any spaces. Also, you can use ``-q`` multiple times to make multiple queries at once. For one, a query can be a software name / title like 'Apache 2.4.39' or 'Wordpress 5.7.2'. Furthermore, a query can also be a [CPE 2.3](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe) string.

Here are some examples:
* Query *Sudo 1.8.2* for known vulnerabilities:
  ```bash
  $ ./search_vulns.py -q 'Sudo 1.8.2'

  [+] Sudo 1.8.2 (cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*)
  CVE-2019-14287 (CVSSv3.1/8.8): In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.
  Exploits:  https://www.exploit-db.com/exploits/47502
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2019-14287, 2019-10-17
  CVE-2017-1000368 (CVSSv3.0/8.2): Todd Miller's sudo version 1.8.20p1 and earlier is vulnerable to an input validation (embedded newlines) in the get_process_ttyname() function resulting in information disclosure and command execution.
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2017-1000368, 2017-06-05
  [...]
  ```
* Query *Moodle 3.4.0* for known vulnerabilities:
  ```bash
  $ ./search_vulns.py -q 'Moodle 3.4.0'

  [+] Moodle 3.4.0 (cpe:2.3:a:moodle:moodle:3.4.0:-:*:*:*:*:*:*)
  CVE-2018-14630 (CVSSv3.0/8.8): moodle before versions 3.5.2, 3.4.5, 3.3.8, 3.1.14 is vulnerable to an XML import of ddwtos could lead to intentional remote code execution. When importing legacy 'drag and drop into text' (ddwtos) type quiz questions, it was possible to inject and execute PHP code from within the imported questions, either intentionally or by importing questions from an untrusted source.
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2018-14630, 2018-09-17
  CVE-2018-1133 (CVSSv3.0/8.8): An issue was discovered in Moodle 3.x. A Teacher creating a Calculated question can intentionally cause remote code execution on the server, aka eval injection.
  Exploits:  https://www.exploit-db.com/exploits/46551
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2018-1133, 2018-05-25
  [...]
  ```
Again, note that when *search_vulns* is initially installed, it takes quite some time to setup the local vulnerability and software database.

## Running a Web Server
It is also possible to run a web server that provides this tool's functionality to clients over the network. ``web_server.py`` contains a working example using Flask. Depending on your environment, you may want to modify the server ip and port at the end of this file. To run a simple Flask web server, just run:
```bash
./web_server.py
```
Furthermore, you can use ``gunicorn`` to make the web server more scalable; for example by running:
```bash
gunicorn --worker-class=gevent --worker-connections=50 --workers=3 --bind '0.0.0.0:8000' wsgi:app
```
You can read more about choosing good ``gunicorn`` settings for your system [here](https://medium.com/building-the-system/gunicorn-3-means-of-concurrency-efbb547674b7). Note, however, that this tool is quite CPU and memory intensive, meaning that scalability is somewhat limited.

Finally, you can also use Nginx as a reverse proxy. A sample configuration file is provided in [``web_server_files/nginx.conf.sample``](https://github.com/ra1nb0rn/search_vulns/blob/master/web_server_files/nginx.conf.sample). Again, you may have to adjust this to your needs. When using Nginx, make sure you have the app running at the configured endpoint(s). For the sample configuration file, for example, you would have to run something similar to the following:
```bash
gunicorn --worker-class=gevent --worker-connections=50 --workers=3 --bind 'unix:/tmp/gunicorn.sock' wsgi:app
```

## License
*search_vulns* is licensed under the MIT license, see [here](https://github.com/ra1nb0rn/search_vulns/blob/master/LICENSE).
