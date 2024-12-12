#!/usr/bin/env python3

import subprocess
from bs4 import BeautifulSoup

from .update_generic import *
from .update_distributions_generic import *

ROOT_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(1, ROOT_PATH)

MATCH_RELEVANT_RHEL_CPE = re.compile(r'cpe:\/[ao]:redhat:(?:enterprise_linux|rhel_[\w]{3}):([0-9\.]{1,3})')
MATCH_RHEL_VERSION_IN_PACKAGE = re.compile(r'\.[Ee][Ll](\d{1,2}[_\.]\d{1,2})[_\.]?\d{0,2}')
GITHUB_REDHAT_API_DATA_URL = 'https://github.com/aquasecurity/vuln-list-redhat.git'
REQUEST_HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/62.0'}
REDHAT_MAPPING_VERSION_CODENAME_URL = 'https://docs.fedoraproject.org/en-US/quick-docs/fedora-and-red-hat-enterprise-linux/'
REDHAT_EOL_DATA_API_URL = 'https://endoflife.date/api/rhel.json' 
REDHAT_DATAFEED_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'redhat_data_feeds')

REDHAT_NOT_FOUND_NAME = {}
REDHAT_RELEASES = {}
REDHAT_UPDATE_SUCCESS = None


def rollback_redhat():
    '''Performs rollback specific for redhat'''
    rollback()
    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)


def get_redhat_api_data():
    '''Download RedHat Api data from GitHub'''

    # Thanks to aquasecurity for providing the data of 
    # the RedHat Security API in a GitHub Repository
    # https://github.com/aquasecurity/vuln-list-redhat/tree/main

    if os.path.isdir(REDHAT_DATAFEED_DIR):
        shutil.rmtree(REDHAT_DATAFEED_DIR)

    # download RedHat data from a GitHub Repo
    return_code = subprocess.call(
        'git clone -n --depth 1 --filter=tree:0 %s \'%s\''
        % (GITHUB_REDHAT_API_DATA_URL, REDHAT_DATAFEED_DIR),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception('Could not download latest resources of RedHat Api from GitHub'))

    # extract only relevant data
    return_code = subprocess.call(
        'cd %s; git sparse-checkout set --no-cone api; git checkout'
        % (REDHAT_DATAFEED_DIR,),
        shell=True,
        stderr=subprocess.DEVNULL
    )
    if return_code != 0:
        raise (Exception('Could not download latest resources of RedHat Api from GitHub'))


def get_redhat_version_codename_mapping():
    global REDHAT_UPDATE_SUCCESS

    # download data
    try:
        redhat_mapping_initial_response = requests.get(url=REDHAT_MAPPING_VERSION_CODENAME_URL, headers=REQUEST_HEADERS)
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}')
        rollback_redhat()
        return f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}'
    if redhat_mapping_initial_response.status_code != requests.codes.ok:
        REDHAT_UPDATE_SUCCESS = False
        rollback_redhat()
        communicate_warning(f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}; received a non-ok response code.')
        return f'An error occured when making initial request to {REDHAT_MAPPING_VERSION_CODENAME_URL}; received a non-ok response code.'

    # extract data from table
    soup = BeautifulSoup(redhat_mapping_initial_response.text, "html.parser")
    try:
        table = soup.find('table', class_='tableblock frame-all grid-all stretch')
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'An error occured when trying to parse the table for redhat version-codename-mapping from {REDHAT_MAPPING_VERSION_CODENAME_URL}')
        rollback_redhat()
        return f'An error occured when trying to parse the table for redhat version-codename-mapping from {REDHAT_MAPPING_VERSION_CODENAME_URL}'
    
    global REDHAT_RELEASES
    # hardcode mapping of first release because it is easier
    REDHAT_RELEASES['2.1'] = 'panama'
    # skip table header and the first two lines of the table
    for row in table.find_all('tr')[3:]:
        release, codename = row.find_all('td')[:2]
        release, codename = release.text.split()[-1], codename.text.lower()
        REDHAT_RELEASES[release] = codename


def get_redhat_eol_data():
    global REDHAT_UPDATE_SUCCESS

    headers = {'accept': 'application/json'}
 
    try:
        redhat_eol_api_response = requests.get(url=REDHAT_EOL_DATA_API_URL, headers=headers)
    except:
            REDHAT_UPDATE_SUCCESS = False
            communicate_warning(f'An error occured when making request to {REDHAT_EOL_DATA_API_URL}')
            rollback_redhat()
            return f'An error occured when making request to {REDHAT_EOL_DATA_API_URL}'
    if redhat_eol_api_response.status_code != requests.codes.ok:
        REDHAT_UPDATE_SUCCESS = False
        rollback_redhat()
        communicate_warning(f'An error occured when making initial request to {REDHAT_EOL_DATA_API_URL}; received a non-ok response code.')
        return f'An error occured when making initial request to {REDHAT_EOL_DATA_API_URL}; received a non-ok response code.'

    return redhat_eol_api_response.json()


def initialize_redhat_release_version_codename(config):
    '''Download redhat release data via redhat Security API'''
    
    if not QUIET:
        print('[+] Downloading RedHat version-codename-mapping data')

    get_redhat_version_codename_mapping()
    redhat_eol_json = get_redhat_eol_data()

    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()
    query = 'INSERT INTO distribution_codename_version_mapping (source, version, codename, support_expires, esm_lts_expires) VALUES (?, ?, ?, ?, ?)'

    # extract codename and version from json
    for release in redhat_eol_json:
        main_version = release['cycle']
        codename = REDHAT_RELEASES[main_version]
        support_expires = str(release['support'])
        esm_expires = str(release['extendedSupport'])
        latest_version = str(release['latest'])
        for i in range(int(latest_version.split('.')[1])+1):
            version =  main_version+'.'+str(i)
            # codename to empty string b/c only base entry gets a codename
            db_cursor.execute(query, ('redhat', version, '', support_expires, esm_expires))
        db_cursor.execute(query, ('redhat', main_version, codename, support_expires, esm_expires))

    # add versions with no eol data
    for main_version, codename in REDHAT_RELEASES.items():
        if float(main_version)>=float(redhat_eol_json[-1]['cycle']):
            break
        if main_version == '3':
            count_subversions = 10
        elif main_version == '2.1':
            count_subversions = 8
        for i in range(count_subversions):
            version = main_version+'.'+str(i)
            db_cursor.execute(query, ('redhat', version, codename, '', ''))

    db_conn.commit()
    db_conn.close()


def add_package_status_to_not_found(cve_id, matching_cpe, name, name_version, redhat_version, version_end, extra_cpe):
    '''Add given given redhat version in a package to REDHAT_NOT_FOUND_NAME'''
    global REDHAT_NOT_FOUND_NAME
    try:
        REDHAT_NOT_FOUND_NAME[name].append((version_end, redhat_version, cve_id, name_version, matching_cpe, extra_cpe))
    except:
        REDHAT_NOT_FOUND_NAME[name] = [(version_end, redhat_version, cve_id, name_version, matching_cpe, extra_cpe)]


def _get_matching_cpe(package_name, original_package_name, base_package_name, version_end, search, cpes):
    '''Get matching cpe for the given package'''
    matching_cpe, perfect_match = get_matching_cpe(package_name, original_package_name, version_end, search, cpes)
    # search with base_package_name if no cpe found
    if matching_cpe == 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*':
        iter_matching_cpes = iter(search_cpes(base_package_name, threshold=0.42, count=7).values())
        matching_cpes = next(iter_matching_cpes)
        if matching_cpes and matching_cpes[0][1] > 0.80:
            matching_cpe = matching_cpes[0][0]
            perfect_match = False
    return matching_cpe, perfect_match


def process_cve(cve, db_cursor):
    '''Get cpes for all packages in a cve and add these information to the db'''
    cve_id = cve['cve_id']
    cpes = cve['cpes']
    packages = cve['affected_release'] + cve['package_state']
    general_given_cpes = [get_general_cpe(cpe[1]) for cpe in cpes if cpe[1].split(':')[2] == 'a']

    # skip cve if only hardware cpes
    if cpes and are_only_hardware_cpes(cpes):
        return

    packages_cpes = []
    # list of (version_end, redhat_version, package_name.lower())
    relevant_package_infos = process_relevant_package_infos(packages) 

    package_names = sorted([name[2] for name in relevant_package_infos])

    # get basename for all packages to avoid using the same cpe for different packages
    relevant_packages = add_basename_to_package_names(relevant_package_infos, package_names)

    for package_name, base_name_package, relevant_package_info in relevant_packages:

        relevant_package_info.sort(key = lambda status:float(status[1]))

        # only try to summarize if more than 2 infos are given
        if len(relevant_package_info) > 2:
            relevant_package_info = remove_duplicates(relevant_package_info)
            relevant_package_info_summarized = summarize_statuses_with_version(relevant_package_info, summarize_skipping_versions=False, dev_distro_name='upstream')
        
            relevant_package_info_summarized.sort(key = lambda status:float(status[1]))
        else:
            relevant_package_info_summarized = relevant_package_info

        # force >= as operator for the highest enry of important packages
        if relevant_package_info_summarized[-1][1] == relevant_package_info[-1][1] and not relevant_package_info_summarized[-1][2] and len(cpes) == 0 and package_name == base_name_package:
            relevant_package_info_summarized[-1] = (relevant_package_info_summarized[-1][0], relevant_package_info_summarized[-1][1], '>=')

        matching_cpe = ''
        original_package_name = package_name
        package_name, name_version = split_name(package_name)
        add_to_vuln_db_bool = True

        # iterate through all rhel versions of a package
        for version_end, redhat_version, extra_cpe in relevant_package_info_summarized:

            if not version_end:
                continue

            # add to not found if initial cpe search wasn't successful
            if not add_to_vuln_db_bool:
                add_package_status_to_not_found(cve_id, matching_cpe, package_name, name_version, redhat_version, version_end, extra_cpe)
                continue

            # get matching cpe if not already found
            if not matching_cpe:
                perfect_match = True
                name_version, search = get_search_version_string(package_name, name_version, version_end)
                if len(package_names) == 1 and len(general_given_cpes) == 1 and package_name in general_given_cpes[0] and package_name != 'linux':
                    matching_cpe = general_given_cpes[0]
                else:
                    matching_cpe, perfect_match = _get_matching_cpe(package_name, original_package_name, base_name_package, version_end, search, cpes)

                # linux.* package
                if not matching_cpe:
                    break

                matching_cpe = get_general_cpe(matching_cpe)

                # no valid cpe found
                if matching_cpe == 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*':
                    add_package_status_to_not_found(cve_id, matching_cpe, package_name, name_version, redhat_version, version_end, extra_cpe) 
                    add_to_vuln_db_bool = False
                    matching_cpe = ''
                    continue

                # handle different package with similar names
                matching_cpe_parts = get_cpe_parts(matching_cpe)
                if base_name_package != package_name and matching_cpe_parts[4] == base_name_package:
                    matching_cpe_parts[4] = package_name
                    matching_cpe = ':'.join(matching_cpe_parts)
                elif not perfect_match:
                    # check whether similarity between name and cpe is high enough
                    sim_score = cpe_matching_score(package_name, matching_cpe)
                    if sim_score < PACKAGE_CPE_MATCH_THRESHOLD:
                        add_package_status_to_not_found(cve_id, matching_cpe, package_name, name_version, redhat_version, version_end, extra_cpe) 
                        add_to_vuln_db_bool = False
                        matching_cpe = ''
                        continue

                # add packages to found packages for cve
                if add_to_vuln_db_bool:
                    packages_cpes.append((matching_cpe, package_name, name_version))
                else:
                    continue

                # match found cpe to all previous not found packages
                match_not_found_cpe(cpes, matching_cpe, package_name, db_cursor)

            # remove .el<REDHAT_VERSION> from version_end
            version_end = re.sub(r'\.el[0-9]{1,2}', '', version_end)

            # add eol entry if no nvd entry and all given entries eol  or most recent distribution not-affected
            if version_end == '-2':
                if not matching_cpe in general_given_cpes and \
                    (relevant_package_info_summarized[-1][0] == '-1' or all([ver_end[0]=='-2' for ver_end in relevant_package_info_summarized])):
                    version_end = str(sys.maxsize)
                else:
                    continue

            distro_cpe= get_distribution_cpe(redhat_version, 'rhel', matching_cpe, extra_cpe)
            add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'redhat', db_cursor)


def remove_duplicates(relevant_package_info):
    '''Remove duplicate entries that occur if infos for different RedHat products is given'''
    unique_relevant_package_info = []
    for version_end, redhat_version, operator in relevant_package_info:
        if unique_relevant_package_info and unique_relevant_package_info[-1][1] == redhat_version:
            if CPEVersion(unique_relevant_package_info[-1][0]) > CPEVersion(version_end):
                continue
            else:
                unique_relevant_package_info.pop()
        unique_relevant_package_info.append((version_end, redhat_version, operator))
    return unique_relevant_package_info


def process_relevant_package_infos(packages):
    '''Return list of all package infos in format (version_end, redhat_version, package_name)'''
    relevant_package_infos = []
    redhat_version = ''
    for package in packages:
        redhat_version_exact = ''
        redhat_cpe = package['cpe']
        # only process RHEL information, no subproduct of RHEL like 'Red Hat Enterprise Linux 8.6 Update Services for SAP Solutions'
        if not MATCH_RELEVANT_RHEL_CPE.match(redhat_cpe):
            continue
        redhat_version = MATCH_RELEVANT_RHEL_CPE.match(redhat_cpe).group(1)
        # package is fixed
        if 'package' in package.keys():
            # no version given, e.g. 'kpatch-patch'
            if not any(char.isdigit() for char in package['package']):
                continue
            # try to get fixed version from package name
            if ':' in package['package']:
                package_name, version = package['package'].split(':', maxsplit=1)
            elif '-' in package['package']:
                package_name, version = package['package'].split('-', maxsplit=1)
            else:
                # e.g. dotnet7.0
                package_name, version = re.match(r'([a-z]*)([0-9\.]*)', package['package']).groups()
        # package not fixed
        elif 'fix_state' in package.keys():
            package_fix_state = package['fix_state']
            package_name = package['package_name']
            if package_fix_state in ['Affected', 'Fix deferred', 'New', 'Will not fix']:
                version = str(sys.maxsize-1)
            elif package_fix_state == 'Under investigation':
                version = str(sys.maxsize)
            elif package_fix_state == 'Not affected':
                version = '-1'
            # Missing state: 'Out of support scope' -> a product could be fixed by Extended life cycle support (ELS, paid), but not with the standard license -> has an extra entry therefore ignored here
            # use version_end = -2 to represent this
            else:
                version = '-2'
        if not redhat_version:
            continue
        # remove attached '-0' to some package names
        if package_name[-2:] == '-0':
            package_name = package_name[:-2]
        # get exact redhat version from package if something like 'RedHat Enterprise Linux 7' is given
        # add two entries to database, one general and one specific
        if len(redhat_version.split('.')) == 1 and MATCH_RHEL_VERSION_IN_PACKAGE.search(version):
            redhat_version_exact = MATCH_RHEL_VERSION_IN_PACKAGE.search(version).group(1).replace('_', '.')
        # change 'container-tools:4.0/podman' to 'podman4.0'
        if (':') in package_name and ('/') in package_name:
            package_name_parts = package_name.split(':')[1].split('/', maxsplit=1)
            package_name = package_name_parts[1]
            # only add something like 2.4 to package_name, not rhel8
            if '.' in package_name_parts[0]:
                package_name += package_name_parts[0]
        version_end = get_clean_version(version, is_good_version=True)
        relevant_package_infos.append((version_end, redhat_version, package_name.lower()))
        # add two entries to database, one general and one specific
        if redhat_version_exact:
            relevant_package_infos.append((version_end, redhat_version_exact, package_name.lower()))
    return relevant_package_infos


def match_not_found_cpe(cpes, matching_cpe, name, db_cursor):
    '''Add all not found entries with the same package name to vuln_db after a matching cpe was found'''
    global REDHAT_NOT_FOUND_NAME
    try:
        backport_cpes = REDHAT_NOT_FOUND_NAME[name]
        for version_end, redhat_version, cve_id, name_version, _, extra_cpe in backport_cpes:
            distro_cpe = get_distribution_cpe(redhat_version, 'rhel', matching_cpe, extra_cpe)
            if version_end:
                add_to_vuln_db(cve_id, version_end, matching_cpe, distro_cpe, name_version, cpes, 'redhat', db_cursor)
        del REDHAT_NOT_FOUND_NAME[name]
    except:
        pass


def get_redhat_data_from_files():
    '''Extract the cve data from redhat api data, saved in files'''
    cves_redhat = []
    api_path = os.path.join(REDHAT_DATAFEED_DIR, 'api')

    for dir in os.listdir(api_path):
        for filename in os.listdir(os.path.join(api_path, dir)):
            with open(os.path.join(api_path, dir, filename), 'r') as f:
                res_json = json.load(f)
                if not res_json:
                    print('[!] RedHat download failed')
                    communicate_warning('RedHat download failed')
                    rollback_redhat()
                    return 'RedHat download failed'
            cves_redhat.append(res_json)
            continue
    cves_redhat.sort(key=lambda cve: cve['name'])    
    return cves_redhat


def merge_redhat_with_nvd_data(config):
    '''Add already found information like cpes to the cves from RedHat'''
    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    # get cve data from vuln_db
    query = 'SELECT cve_id, cpe, cpe_version_start, is_cpe_version_start_including, cpe_version_end FROM cve_cpe WHERE source == "nvd"'
    cve_cpe_list = db_cursor.execute(query, ()).fetchall()
    cve_cpe_list.sort(key=lambda cve: cve[0])
    db_conn.close()
    
    cves_redhat = get_redhat_data_from_files()
    cve_cpe_redhat = []
 
    pointer_cves_nvd = 0
    pointer_cve_cpe_redhat = 0
    found = False   # used for cves which occur more than one time in the cve_cpe_table
    length_cve_cpe_list = len(cve_cpe_list)

    # match cve and cpe
    for cve in cves_redhat:
        cve_id = cve['name']
        # fixed packages
        affected_release = cve['affected_release']
        if not affected_release:
            affected_release = []
        
        # not fixed packages
        package_state = cve['package_state'] 
        if not package_state:
            package_state = []

        # iterate through all cves from nvd
        for i in range(pointer_cves_nvd, length_cve_cpe_list):
            nvd_cve_id = cve_cpe_list[i][0]
            if cve_id ==  nvd_cve_id:
                if not found:
                    cve_cpe_redhat.append({'cve_id': cve_id, 'cpes': [], 'affected_release': affected_release, 'package_state': package_state})
                    found = True
                cve_cpe_redhat[pointer_cve_cpe_redhat]['cpes'].append(cve_cpe_list[i])                           
            elif found:
                found = False
                pointer_cve_cpe_redhat += 1
                pointer_cves_nvd = i
                break
        # cve_id not found in cve_cpe
        else:
            if is_cve_rejected(cve_id, config):
                continue
            else:
                cve_cpe_redhat.append({'cve_id': cve_id, 'cpes': [], 'affected_release': affected_release, 'package_state': package_state})
                pointer_cve_cpe_redhat += 1

    cves_redhat = []
    cve_cpe_list = []
    return cve_cpe_redhat


def process_data(config):
    '''Process RedHat api data'''
    if not QUIET:
        print('[+] Adding RedHat data to database')

    cve_cpe_redhat = merge_redhat_with_nvd_data(config)

    db_conn = get_database_connection(config['DATABASE'], config['DATABASE_NAME'])
    db_cursor = db_conn.cursor()

    # process every cve
    for cve in cve_cpe_redhat:
       process_cve(cve, db_cursor)

    # add all not found packages to vuln_db
    add_not_found_packages(REDHAT_NOT_FOUND_NAME, 'redhat', db_cursor) 

    db_conn.commit()
    db_conn.close()


async def update_vuln_redhat_db(config):
    '''Update the vulnerability database for redhat'''

    global REDHAT_UPDATE_SUCCESS

    if not QUIET:
        print('[+] Downloading RedHat data feeds')

    try:
        get_redhat_api_data()
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning(f'Could not download RedHat vuln data from {GITHUB_REDHAT_API_DATA_URL}.')
        rollback_redhat()
        return f'Could not download RedHat vuln data from {GITHUB_REDHAT_API_DATA_URL}.'

    # get redhat releases data
    initialize_redhat_release_version_codename(config)

    try:
       process_data(config)
    except:
        REDHAT_UPDATE_SUCCESS = False
        communicate_warning('Could not process vuln data from the RedHat Security Api')
        rollback_redhat()
        return 'Could not process vuln data from the RedHat Security Api'
    
    shutil.rmtree(REDHAT_DATAFEED_DIR)
    return False