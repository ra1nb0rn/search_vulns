# search_vulns
Search for known vulnerabilities in software using software titles or a CPE 2.3 string.

## About
*search_vulns* can be used to search for known vulnerabilities in software. To achieve this, the tool utilizes a locally built vulnerability database, currently containing CVE information from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) and exploit information from the [Exploit-DB (EDB)](https://www.exploit-db.com/). Using the *search_vulns* tool, this local information can be queried, either by providing software titles like 'Apache 2.4.39' or by providing a CPE 2.3 string like ``cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*``.

## Installation
To install this tool, simply run the ``install.sh`` script. This script automatically installs the required dependencies and initiates the first build of the local vulnerability database. Note that the first build of the local vulnerability database can take quite some time, since EDB information can only be pulled relatively slowly; 30+ minutes of build time is expected. Of course, you can also look at the installation script and setup everything manually. Finally, you can also use the provided ``Dockerfile`` to build a container:
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
usage: search_vulns.py [-h] [-u] [-o OUTPUT] [-q QUERY]

Search for known vulnerabilities in software -- Created by Dustin Born (ra1nb0rn)

optional arguments:
  -h, --help            show this help message and exit
  -u, --update          Update the local vulnerability and software database
  -o OUTPUT, --output OUTPUT
                        File to output found vulnerabilities to (JSON)
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
* Query *Proftpd 1.3.3c* for known vulnerabilities:
  ```bash
  $ ./search_vulns.py -q 'Proftpd 1.3.3c'

  [+] Proftpd 1.3.3c (cpe:2.3:a:proftpd:proftpd:1.3.3:c:*:*:*:*:*:*)
  CVE-2010-4221 (CVSSv2.0/10.0): Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute arbitrary code via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.
  Exploits:  https://www.exploit-db.com/exploits/15449
             https://www.exploit-db.com/exploits/16851
             https://www.exploit-db.com/exploits/16878
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2010-4221, 2010-11-09
  CVE-2019-12815 (CVSSv3.0/9.8): An arbitrary file copy vulnerability in mod_copy in ProFTPD up to 1.3.5b allows for remote code execution and information disclosure without authentication, a related issue to CVE-2015-3306.
  Reference: https://nvd.nist.gov/vuln/detail/CVE-2019-12815, 2019-07-19
  ```
Again, note that when *search_vulns* is initially installed, it takes quite some time to setup the local vulnerability and software database.

## License
*search_vulns* is licensed under the MIT license, see [here](https://github.com/ra1nb0rn/search_vulns/blob/master/LICENSE).
