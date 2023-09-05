# Changelog
This file keeps track of all notable changes between the different versions of search_vulns.

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
