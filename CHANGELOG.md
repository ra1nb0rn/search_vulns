# Changelog
This file keeps track of all notable changes between the different versions of search_vulns.

## v0.5.1 - 2024-04-26
### Added
- A flag to use the best matching *created* CPE automatically in CLI.
- A flag to print search_vulns version.
- endoflife.date data is now also reported for deprecated / equivalent CPEs.
- Add CPEs only contained in the NVD's vuln data to the CPE-DB.
- Add references to blog posts and a public instance.

### Fixed
- Install of dependencies in automated install script.
- Some bug fixes and improvements in web frontend.
- Improvements to version comparison for more complex version numbers.
- Setting up the API tables if the database already existed.
- Fix pipeline to rebuild release assets regularly.


## v0.5.0 - 2024-04-13
### Added
- Added a completely new web frontend, which is not just more beautiful but also comes with
  additional functionalities.
- Added endoflife.date as new data source.
- Added information from CISA about known exploited vulnerabilities.
- The web server can be configured to use reCAPTCHA protection and manage API keys.
- The web server now provides an official API.
- Added MariaDB as second database option.
- Vulnerability search is now more accurate by managing some of the NVD's
  poorly formatted entries better.
- Added an option to return vulnerabilities, which only apply to one singular product
  version according to the NVD entry, when an earlier version is queried.
- Added equivalent CPEs and improvements in cpe_search.
- Use an additional resource for equivalent CPEs from Debian.
- Implement more extensive CPE creation capabilities.

### Changed
- CPE creation was moved into the cpe_search module.
- The vulnerability search code was deduplicated.
- The vulnerability search code was simplified.
- Improved cpe_search such that a more holistic view of all available CPEs for a
  query is provided.
- Removed the unused "with_cpes" column from the vulnerability database.
- Removed the in-memory mode if SQLite is used.
- Improved version comparison with complex versions or somewhat artifical versions
  created by the NVD.
- Update test cases with new data and coverage of new functionalities.
- Created a separate resource folder to store resources in.
- Improve performance.

### Fixed
- Fixed some small bugs here and there.


## v0.4.13 - 2024-02-22
### Added
- Store a client's configuration in the web app persistently on the client.
- Improve CPE retrieval for THE Flask from PalletsProjects.

### Fixed
- Display bug of related queries in web frontend.
- Bug in version comparison with more complex versions.
- Bug in update process with custom config file.


## v0.4.12 - 2024-02-06
### Added
- New config file concept, which simplifies a web server deployment
- Individual words in user queries are weighed to improve the matching of query to CPE.
- Tooltip for EDB checkbox in web app
- Equivalent CPE for Kubernetes API server

### Changed
- The version detection in queries has been improved, such that more new CPEs can be created.
- Don't keep track of cveid_to_edbid.json mapping in GitHub repo any more.

### Fixed
- Update test cases with new vulns.


## v0.4.11 - 2024-01-09
### Fixed
- Update test cases with new vulns and exploits.


## v0.4.10 - 2023-12-21
### Fixed
- Update test cases with new exploits.
- Strip user queries before macthing them to a CPE.


## v0.4.9 - 2023-12-12
### Added
- Update cpe_search submodule and adapt search_vulns code to it:
    - cpe_search uses an improved matching algorithm with weights
    - create more alternative queries, e.g. for JS packages and Bootstrap
    - fixes some bugs in cpe_search

### Fixed
- Update test cases with new exploits.


## v0.4.8 - 2023-12-08
### Added
- Equivalent CPEs for Amanda Network Backup, Apport, AppArmor and Accountsservice

### Changed
- Update cpe_search and adapt to its updated interface.

### Fixed
- Update test cases with new CVEs and exploits.


## v0.4.7 - 2023-11-29
### Fixed
- Fixed bug in cpe_search if a query with the keyword "for" was made
- Fixed caching bug in search_vulns web server


## v0.4.6 - 2023-11-27
### Added
- New CPE equivalence for Swagger UI
- Update CVE <-> EDB mapping

### Fixed
- Update test cases with new CVE and exploit.


## v0.4.5 - 2023-11-09
### Added
- New CPE equivalence for Handlebars.js.
- New test cases for Handlebars.js.

### Fixed
- Expand CPE wildcard replacement when searching for vulnerabilities with an exactly matching CPE.


## v0.4.4 - 2023-11-08
### Fixed
- Update test cases with new CVE.


## v0.4.3 - 2023-11-01
### Fixed
- Update test cases with new CVEs and CPEs.


## v0.4.2 - 2023-10-24
### Fixed
- Update test cases with new CVEs and exploits.


## v0.4.1 - 2023-10-16
### Fixed
- The scheduled workflow to update release assets now references the new CPE dictionary file.


## v0.4.0 - 2023-10-14
### Changed
- Speed up the search of CPEs even more. To achieve this, more data required by the match algorithm is precomputed now. Also, the file format of the CPE dictionary was changed from CSV to SQLite. Finally, a memory-based variant was brought back for the CPE search.


## v0.3.0 - 2023-10-12
### Added
- A script to run all tests at once.
- Web UI: Highlight likely false positive if a vulnerability only affect a general CPE.
- Manually added equivalent CPE entries for multiple Citrix products.

### Changed
- Changed scheduled workflow for building resources, such that no new release is created. Instead the latest release is updated with the latest artifacts.
- Changed the test workflow, such that the DB is only rebuilt if its build code has changed.
- Manual entries for equivalent CPEs are now stored in a separate file.
- Speed up the search of CPEs by modifying the underlying algorithm. Also remove the memory-based algorithm for CPE search.

### Fixed
- Some minor bugs


## v0.2.0 - 2023-09-05
### Added
- Various improvements for matching a text query to a CPE via the [cpe_search](https://github.com/ra1nb0rn/cpe_search) submodule, which was updated multiple times.
- A web server frontend based on Flask was added. This makes it easier to use the tool and allows for some user interaction.
- In-depth exporting functionality for vulnerability data in web frontend as CSV or Markdown.
- Show alternative queries in web frontend if a CPE match for the user query could not be found automatically.
- Creation of new CPEs in web frontend, based on user query and existing CPEs.
- Include NVDs exploit references in web frontend.
- Add exploit references from PoC-in-GitHub.
- Add testing pipeline and test cases.
- Consider deprecated CPEs or more than one CPE for the same product when searching for vulnerabilities (e.g. Piwik --> Matomo).

### Changed
- All resource data can now be kept in memory. If this is enabled, subsequent queries get processed significantly faster, at the cost of occupying more memory. By default, only the web server has this option enabled and loads all data into memory upon startup. The CLI, however, is meant to run memory-efficient and only loads required data as necessary.
- Use the NVD's CVE and CPE APIs instead of its now legacy data feeds.

### Fixed
- Loads of bugs, old ones and new ones.
- Improved parsing of the NVD's vulnerability and software data.
- Fixed link to Exploit-DB repo, because the GitHub project was archived and moved to GitLab.


## v0.1.2 - 2022-01-22

### Changed
- Reduce build frequency of vulnerability and software databases via GitHub workflow.
- Delete last soft release when a new soft release is published. "Soft" release means that only the resource files were updated.


## v0.1.1 - 2022-01-21

### Added
- Add a GitHub workflow to build the vulnerability and software databases automatically on push to master branch and once every couple of days.

### Changed
- Instead of building the software and vulnerability resource files manually every time on install / update, these files are now downloaded from the latest release on GitHub.


## v0.1.0 - 2022-01-20

### Added
- Initial release of the tool.
