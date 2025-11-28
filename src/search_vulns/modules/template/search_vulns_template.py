
# This serves as a template file for new modules.
# In general all modules have to reside in the "modules/"
# subdirectory and be prefixed with "search_vulns_" and be
# Python files. A module can define various methods which
# will be called by search_vulns' core.

# absolute import necessary, since modules are loaded dynamically
# from search_vulns.vulnerability import Vulnerability

### INFLUENCING MODULE ORDER ###
# Declare which modules have to have been ran before this module is
# invoked (see examples in other modules).
# e.g. for build process:
# REQUIRES_BUILT_MODULES = ['ghsa.search_vulns_ghsa', 'cpe_search.search_vulns_cpe_search']
# e.g. for search_vulns process:
# REQUIRES_RAN_MODULES = ['ghsa.search_vulns_ghsa', 'cpe_search.search_vulns_cpe_search']


### INSTALLATION ###
# def install():
#     """
#     This method will be called when search_vulns is installed.
#     When this method is called, the current working directory
#     will be the one of the called module.
#     """
#     pass


### DATA UPDATES ###
# def update(productdb_config, vulndb_config, module_config, stop_update):
#     """
#     Runs the soft update process for this module.

#     Args:
#         productdb_config (dict): Configuration to connect to product database.
#         vulndb_config (dict): Configuration to connect to vulnerability database.
#         module_config (dict): Configuration entries of this module.
#         stop_update (multiprocessing.Manager.Event): Signal to stop the update process prematurely.

#     Returns:
#         tuple[bool, list[str]]: A tuple where the first element indicates success (True if the
#         update completed successfully), and the second element is a list of artifacts created
#         during the update.
#     """

#     # Will be invoked when search_vulns performs a soft update
#     # check if update should be stopped globally prematurely via `stop_update.is_set()`
#     # the soft update is intended to be quick and only pull new data without actually building it

#     return True, []


# def full_update(productdb_config, vulndb_config, module_config, stop_update):
#     """
#     Runs the full update process for this module.

#     Args:
#         productdb_config (dict): Configuration to connect to product database.
#         vulndb_config (dict): Configuration to connect to vulnerability database.
#         module_config (dict): Configuration entries of this module.
#         stop_update (multiprocessing.Manager.Event): Signal to stop the update process prematurely.

#     Returns:
#         tuple[bool, list[str]]: A tuple where the first element indicates success (True if the
#         update completed successfully), and the second element is a list of artifacts created
#         during the update.
#     """

#     # will be invoked when search_vulns performs a soft update
#     # check if update should be stopped globally prematurely via `stop_update.is_set()`
#     # the soft update is intended to be quick and only pull new data without actually building it

#     # You can use the productdb_config and vulndb_config to connect to the global product or
#     # vulnerability database. All data stored herein will be pulled during a soft update by
#     # search_vulns automatically. Also, these two databases are managed globally throughout
#     # search_vulns, making interactions with them easier.
#     # use modules.utils.get_database_connection(config) to open a database connection.

#     return True, []


### PREPROCESS QUERIES ###
# def preprocess_query(query, product_ids, vuln_db_cursor, product_db_cursor, config):
#     """
#     Preprocess queries to extract other information and "clean up" query for other modules.
#     Args:
#         query (str): The search string provided by the user or calling process.
#         product_ids (dict): Product IDs already retrieved known or provided, indexed by type.
#         vuln_db_cursor (sqlite or mariadb cursor): Database cursor to query global vulnerability database.
#         product_db_cursor (sqlite3 or mariadb cursor): Cursor for accessing the global product database.
#         config (dict): This module's configuration from the global configuration file.

#     Returns:
#         tuple[str, dict]: A tuple containing a processed query, e.g. having some keywords removed, and
#         a dict containing extra parameters to store for later usage by this or other modules.
#     """

#     return query, {}


### RETRIEVAL OF PRODUCT IDS ###
# def search_product_ids(
#     query, product_db_cursor, current_product_ids, is_product_id_query, config, extra_params
# ):
#     """
#     Searches for product IDs based on the given query, provided product IDs and configuration.

#     Args:
#         query (str): The search string provided by the user or calling process.
#         product_db_cursor (sqlite3 or mariadb cursor): Cursor for accessing the global product database.
#         current_product_ids (dict): Product IDs already retrieved for the query by other modules, indexed by type.
#         is_product_id_query (bool): Whether the query is supposed to already be a concrete product ID.
#         config (dict): This module's configuration from the global configuration file.
#         extra_params (dict): Additional optional parameters that may influence the search logic.

#     Returns:
#         tuple[dict, dict]: A tuple containing a dict of matched product IDs of a given type and a dict
#         of product IDs of a given type that did not fully match but would be likely to.
#     """

#     # This function is invoked by search_vulns to have the module search for and return product IDs
#     # matching the provided query or other product IDs. These product IDs can then be used by other 
#     # modules during vulnerability search.

#     return {}, {}


### SEARCHING FOR VULNERABILITIES ###
# def search_vulns(query, product_ids, vuln_db_cursor, config, extra_params):
#     """
#     Search for vulnerabilities with this module's logic / engine.

#     Args:
#         query (str): The search string or criteria to find relevant vulnerabilities.
#         product_ids (dict): Collection of product IDs search for vulnerabilities, indexed by type.
#         vuln_db_cursor (sqlite or mariadb cursor): Database cursor to query global vulnerability database.
#         config (dict): This module's configuration from the global configuration file.
#         extra_params (dict): Additional optional parameters that can modify the search logic or results.

#     Returns:
#         dict[str, Vulnerability]: A dict containing vulnerabilities, indexed by vulnerability ID.
#     """

#     # This function is invoked by search_vulns to have the module perform actual vulnerability search
#     # via the query or provided product IDs. A cursor to the global vulnerability database is also
#     # provided for simplicity.

#     return {}


### ADDING FURTHER INFORMATION ABOUT VULNERABILITIES ###
# def add_extra_vuln_info(vulns: List[Vulnerability], vuln_db_cursor, config, extra_params):
#     """
#     Add extra information for vulnerabilities. Can be used to add exploit information,
#     tracking information, scores and more. The provided vulnerabilities should be modified
#     directly in place.

#     Args:
#         vulns (list[Vulnerability]): A list of vulnerabilities to which information can be appended.
#         vuln_db_cursor (sqlite or mariadb cursor): Database cursor to query global vulnerability database.
#         config (dict): This module's configuration from the global configuration file.
#         extra_params (dict): Optional parameters that can modify how further information is provided.
#     """

#     # This function allows the module to add further details about the identified vulnerabilities.
#     # This information can include exploits, tracking information, scores and more.


### ADDING FURTHER RESULT DATA APART FROM VULNERABILITIES ###
# def postprocess_results(results, query, vuln_db_cursor, product_db_cursor, config, extra_params):
#     """
#     Add additional results, which are not vulnerabilities, based on the query or
#     retrieved product IDs.

#     Args:
#         results (dict): The search_vulns results before becoming final.
#         query (str): The search string or criteria to find relevant vulnerabilities.
#         vuln_db_cursor (sqlite or mariadb cursor): Database cursor to query global vulnerability database.
#         product_db_cursor (sqlite3 or mariadb cursor): Cursor for accessing the global product database.
#         config (dict): This module's configuration from the global configuration file.
#         extra_params (dict): Additional optional parameters that can modify the search logic or results.

#     Returns:
#         dict: A dict containing retrieved extra information, indexed by a key speciyfing what kind of
#         information was added.
#     """

#     # Here, a module can return any other extra information retrieved for the query. This could be
#     # information about a product's software life cycle or recency.

#     return {}
