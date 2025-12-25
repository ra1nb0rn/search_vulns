#include <SQLiteCpp/SQLiteCpp.h>
// include mariadb
#include <conncpp.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <string>
#include <cstdlib>
#include <climits>
#include <unordered_set>
#include <unordered_map>
#include <regex>
#include "database_wrapper.h"
#include "prepared_statement.h"

extern "C" {
    #include "dirent.h"
}

using json = nlohmann::json;
static int nvd_exploit_ref_id = 0;

struct VagueCpeInfo {
    std::string vague_cpe;
    std::string version_start;
    std::string version_start_type;
    std::string version_end;
    std::string version_end_type;

    bool operator==(const VagueCpeInfo &other) const {
        return vague_cpe == other.vague_cpe &&
                version_start == other.version_start &&
                version_start_type == other.version_start_type &&
                version_end == other.version_end &&
                version_end_type == other.version_end_type;
    }
};

namespace std {
    template<>
    struct hash<VagueCpeInfo> {
        std::size_t operator()(const VagueCpeInfo &vi) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return (hash<string>()(vi.vague_cpe)
                     ^ hash<string>()(vi.version_start)
                     ^ hash<string>()(vi.version_start_type)
                     ^ hash<string>()(vi.version_end)
                     ^ hash<string>()(vi.version_end_type));
        }
    };
}

template<typename T>
void handle_exception(T &e) {
    std::string msg = e.what();
    if ((msg.find("UNIQUE constraint failed") == std::string::npos) && (msg.find("Duplicate entry") == std::string::npos)){
        throw e;
    }
}

bool is_safe_database_name(std::string dbName) {
    // Check if database name contains any special characters or keywords
    std::regex pattern("[^a-zA-Z0-9_-]");

    if (std::regex_search(dbName, pattern)) {
        return false; // Database name is malicious
    }

    return true; // Database name is safe
}


int add_to_db(DatabaseWrapper *db, const std::string &filepath) {
    // Begin transaction
    db->start_transaction();
    // get prepared statements
    PreparedStatement* cve_query = db->get_cve_query();
    PreparedStatement* cve_cpe_query = db->get_cve_cpe_query();
    PreparedStatement* add_nvd_exploits_ref_query = db->get_add_nvd_exploits_ref_query();
    PreparedStatement* add_nvd_exploits_ref_indirect_query = db->get_add_nvd_exploits_ref_indirect_query(); 

    // read a JSON file
    std::ifstream input_file(filepath);
    json vulns_json;
    input_file >> vulns_json;

    json metrics_entry, references_entry;
    std::string cve_id, description, published, last_modified, vector_string, severity;
    std::string cvss_version, ref_url, op;
    std::unordered_map<std::string, int> nvd_exploits_refs;
    std::unordered_map<std::string, std::unordered_set<int>> cveid_exploits_map;
    std::list<std::string> cvss_keys = {"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"};
    std::list<std::string> cvss_scorer_types = {"Primary", "Secondary"};
    std::size_t datetime_dot_pos;
    bool vulnerable, cisa_known_exploited, is_general_cpe;
    double base_score;
    int cur_node_id, colon_count, cur_outer_node_idx;

    // iterate the array
    for (auto &cve_entry : vulns_json["vulnerabilities"]) {
        cve_id = cve_entry["cve"]["id"];
        base_score = -1;
        cvss_version = "";
        vector_string = "";
        severity = "";

        // skip rejected entries without content
        if ((cve_entry["cve"]["metrics"].empty() &&
             cve_entry["cve"].find("vulnStatus") != cve_entry["cve"].end() &&
             cve_entry["cve"]["vulnStatus"] == "Rejected")) {
            continue;
        }

        // first retrieve data about CVE and put it into DB
        description = "N/A";
        for (auto &desc_entry : cve_entry["cve"]["descriptions"]) {
            if (desc_entry["lang"] == "en") {
                description = desc_entry["value"];
                break;
            }
        }

        // retrieve CVSS score, vector and severity
        // check which version is used ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
        metrics_entry = cve_entry["cve"]["metrics"];
        for (const auto& cvss_key : cvss_keys) {
            if (base_score != -1)
                break;
            if (metrics_entry.find(cvss_key) != metrics_entry.end()) {
                // iterate all score entries of found CVSS version
                for (auto &metric : metrics_entry[cvss_key]) {
                    if (base_score != -1)
                        break;

                    // try to find "Primary" scorer first and use "Secondary" one as fallback
                    for (auto &cvss_scorer_type : cvss_scorer_types) {  // cvss_scorer_types = {"Primay", "Secondary"}
                        if (metric["type"] == cvss_scorer_type) {
                            base_score = metric["cvssData"]["baseScore"];
                            vector_string = metric["cvssData"]["vectorString"];
                            cvss_version = metric["cvssData"]["version"];

                            if (cvss_version == "2.0")
                                severity = metric["baseSeverity"];
                            else
                                severity = metric["cvssData"]["baseSeverity"];

                            break;
                        }
                    }
                }
            }
        }

        // get published date
        published = cve_entry["cve"]["published"];
        std::replace(published.begin(), published.end(), 'T', ' ');
        datetime_dot_pos = published.rfind(".");
        if (datetime_dot_pos != std::string::npos)
            published = published.substr(0, datetime_dot_pos);

        // get last modified date
        last_modified = cve_entry["cve"]["lastModified"];
        std::replace(last_modified.begin(), last_modified.end(), 'T', ' ');
        datetime_dot_pos = last_modified.rfind(".");
        if (datetime_dot_pos != std::string::npos)
            last_modified = last_modified.substr(0, datetime_dot_pos);

        // mapping of cve to nvd exploits
        references_entry = cve_entry["cve"]["references"];
        for (auto &ref_entry : references_entry) {
            ref_url = ref_entry["url"];
            if (ref_entry.find("tags") != ref_entry.end()) {
                for (auto &tag : ref_entry["tags"]) {
                    if (tag == "Exploit" || tag == "exploit") {
                        if (nvd_exploits_refs.find(ref_url) == nvd_exploits_refs.end()) {
                            nvd_exploits_refs[ref_url] = nvd_exploit_ref_id;
                            nvd_exploit_ref_id++;
                        }
                        if (cveid_exploits_map.find(cve_id) == cveid_exploits_map.end()) {
                            std::unordered_set<int> exploits_refs;
                            cveid_exploits_map[cve_id] = exploits_refs;
                        }
                        cveid_exploits_map[cve_id].emplace(nvd_exploits_refs[ref_url]);
                    }
                }
            }
        }

        // cve in CISA Known Exploited Vulnerabilities Catalog
        cisa_known_exploited = cve_entry["cve"]["cisaExploitAdd"] != nullptr;

        // bind found cve info to prepared statement
        cve_query->bind(1, cve_id);
        cve_query->bind(2, description);
        cve_query->bind(3, published);
        cve_query->bind(4, last_modified);
        
        // Assumption: every entry has at least a cvssV2 score
        cve_query->bind(5, cvss_version);
        cve_query->bind(6, base_score);
        cve_query->bind(7, vector_string);
        cve_query->bind(8, severity);
        cve_query->bind(9, cisa_known_exploited);
        cve_query->execute();

        // Next, retrieve CPE data and put into DB  
        cve_cpe_query->bind(1, cve_id);
        VagueCpeInfo vague_cpe_info;
        for (auto &cve_config_entry: cve_entry["cve"]["configurations"]){
            // assumption 1: the encapsulation depth of logic operators is no more than 2
            // assumption 2: no entry contains "negate":true
            // assumption 3: operator on second level is always "OR"

            if (cve_config_entry.find("operator") != cve_config_entry.end())
                op = cve_config_entry["operator"];
            else
                op = "OR";  // default if no operator explicitly specified

            // fill vector with version information of every mentioned cpe
            std::vector<std::vector<VagueCpeInfo>> all_vulnerable_cpes;
            cur_outer_node_idx = -1;
            for (auto &config_nodes_entry : cve_config_entry["nodes"]) {
                cur_outer_node_idx++;
                std::vector<VagueCpeInfo> node_vulnerable_cpes;

                if (config_nodes_entry.find("cpeMatch") != config_nodes_entry.end()) {
                    for (auto &cpe_entry : config_nodes_entry["cpeMatch"]) {
                        vague_cpe_info = {cpe_entry["criteria"], "", "", "", ""};
                        is_general_cpe = false;

                        if (!cpe_entry["vulnerable"])
                            continue;

                        // check if it's a general CPE in an AND configuration (probably not vulnerable)
                        colon_count = 0;
                        const std::string& criteriaCPE = cpe_entry["criteria"].get_ref<const std::string&>();
                        for (size_t i = 0; i < criteriaCPE.size(); i++) {
                            if (criteriaCPE[i] == ':') {
                                colon_count++;
                                if (colon_count > 4) {
                                    if (i + 1 < criteriaCPE.size()) {
                                        if (criteriaCPE[i + 1] == '*' || 
                                            criteriaCPE[i + 1] == '-' ||
                                            criteriaCPE[i + 1] == '*') {
                                            is_general_cpe = true;
                                        }
                                    }
                                    break;
                                }
                            }
                        }

                        if (cpe_entry.find("versionStartIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartIncluding"];
                            vague_cpe_info.version_start_type = "Including";
                            is_general_cpe = false;
                        }
                        else if (cpe_entry.find("versionStartExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartExcluding"];
                            vague_cpe_info.version_start_type = "Excluding";
                            is_general_cpe = false;
                        }

                        if (cpe_entry.find("versionEndIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndIncluding"];
                            vague_cpe_info.version_end_type = "Including";
                            is_general_cpe = false;
                        }
                        else if (cpe_entry.find("versionEndExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndExcluding"];
                            vague_cpe_info.version_end_type = "Excluding";
                            is_general_cpe = false;
                        }

                        // catch bad entries where the "running on" platform is falsely considered vulnerable, e.g. CVE-2012-6527
                        if (op == "AND" && is_general_cpe && cve_config_entry["nodes"].size() == 2 &&
                            cve_config_entry["nodes"][1-cur_outer_node_idx]["cpeMatch"][0]["vulnerable"] == true) {
                            continue;
                        }

                        node_vulnerable_cpes.push_back(vague_cpe_info);
                    }
                }

                all_vulnerable_cpes.push_back(node_vulnerable_cpes);
            }

            // bind found information to prepared statement
            cur_node_id = -1;
            for (auto &node_vulnerable_cpes : all_vulnerable_cpes) {
                cur_node_id++;

                for (auto &vague_cpe_info : node_vulnerable_cpes) {
                    cve_cpe_query->bind(2, vague_cpe_info.vague_cpe);
                    cve_cpe_query->bind(3, vague_cpe_info.version_start);
                    if (vague_cpe_info.version_start_type == "Including")
                        cve_cpe_query->bind(4, true);
                    else
                        cve_cpe_query->bind(4, false);
                    cve_cpe_query->bind(5, vague_cpe_info.version_end);
                    if (vague_cpe_info.version_end_type == "Including")
                        cve_cpe_query->bind(6, true);
                    else
                        cve_cpe_query->bind(6, false);

                    try {
                        cve_cpe_query->execute();
                    }
                    catch (SQLite::Exception& e) {
                        handle_exception(e);
                    }
                    catch (sql::SQLException& e) {
                        handle_exception(e);
                    }
                }
            }
        }
    } 

    // Put exploit references into DB
    for (auto &exploit : nvd_exploits_refs) {
        add_nvd_exploits_ref_query->bind(1, exploit.second);
        add_nvd_exploits_ref_query->bind(2, exploit.first);
        add_nvd_exploits_ref_query->execute();
    }

    // Put CVEs to NVD exploit refs into DB
    for (auto &mapping_entry : cveid_exploits_map) {
        for (auto &ref_id : mapping_entry.second) {
            add_nvd_exploits_ref_indirect_query->bind(1, mapping_entry.first);
            add_nvd_exploits_ref_indirect_query->bind(2, ref_id);
            add_nvd_exploits_ref_indirect_query->execute();
        }
    }

    // Commit transaction
    db->commit();
    return 1;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 0 == str.compare(str.size()-suffix.size(), suffix.size(), suffix);
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cerr << "Wrong argument count." << std::endl;
        std::cerr << "Usage: ./create_db cve_folder create_sql_statements_file" << std::endl;
        return EXIT_FAILURE;
    }

    // parse args and recover DB config
    std::string cve_folder = argv[1];
    std::ifstream create_sql_statements_file(argv[2]);
    json create_sql_statements = json::parse(create_sql_statements_file);

    json db_config;
    db_config["DATABASE_TYPE"] = std::getenv("DATABASE_TYPE") ?: "";
    db_config["DATABASE_NAME"] = std::getenv("DATABASE_NAME") ?: "";
    db_config["DATABASE_HOST"] = std::getenv("DATABASE_HOST") ?: "";
    db_config["DATABASE_PORT"] = std::getenv("DATABASE_PORT") ?: "";
    db_config["DATABASE_USER"] = std::getenv("DATABASE_USER") ?: "";
    db_config["DATABASE_PASSWORD"] = std::getenv("DATABASE_PASSWORD") ?: "";
    db_config["OVERWRITE_DB"] = std::getenv("OVERWRITE_DB") ?: "";

    std::string database_type = db_config["DATABASE_TYPE"];
    std::string datafeed_filename;
    std::vector<std::string> cve_files;

    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<DatabaseWrapper> db;

    // validate given database name
    if (database_type != "sqlite" && !is_safe_database_name(db_config["DATABASE_NAME"])) {
        std::cout << "Potentially malicious database name detected. Abort creation of database" << std::endl;
        return EXIT_FAILURE;
    }

    try{
        // create database connection
        if (database_type == "sqlite")
            db = std::make_unique<SQLiteDB>(db_config["DATABASE_NAME"]);
        else{
            db = std::make_unique<MariaDB>(db_config);
        } 

        // create tables and prepared statements
        db->execute_query(create_sql_statements["TABLES"]["NVD"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["NVD_CPE"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["NVD_EXPLOITS_REFS"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["NVD_EXPLOITS_REFS_INDIRECT"][database_type]);
        db->create_prepared_statements();

        DIR *dir;
        struct dirent *ent;
        if ((dir = opendir(cve_folder.c_str())) != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                datafeed_filename = ent->d_name;
                if (ends_with(datafeed_filename, ".json"))
                    cve_files.push_back(cve_folder + "/" + datafeed_filename);  // only on unix platforms
            }
            closedir(dir);
        }
        else {
            // could not open directory
            std::cerr << "Could not open directory \'" << cve_folder << "\'" << std::endl;
            return EXIT_FAILURE;
        }
        
        std::cout << "Creating local copy of NVD as " << db_config["DATABASE_NAME"] << " ..." << std::endl;
        for (const auto &file : cve_files) {
            add_to_db(db.get(), file);
        }

        // create view for nvd_exploit_srefs
        db->execute_query(create_sql_statements["VIEWS"]["NVD_EXPLOITS_REFS_VIEW"][database_type]);
    }
    catch (std::exception& e) {
        std::cerr << "exception: " << e.what() << std::endl;
        db->close_connection();
        return EXIT_FAILURE;
    }
    // close database connection
    db->close_connection();

    // print duration of building process
    auto time = std::chrono::high_resolution_clock::now() - start_time;

    std::cout << "Database creation took " <<
    (float) (std::chrono::duration_cast<std::chrono::microseconds>(time).count()) / (1e6) << "s .\n";
    if (database_type == "sqlite") {
        char *db_abs_path = realpath(db_config["DATABASE_NAME"].get<std::string>().c_str(), NULL);
        std::cout << "Local copy of NVD created as " << db_abs_path << " ." << std::endl;
        free(db_abs_path);
    }
    else
        std::cout << "Local copy of NVD created as " << db_config["DATABASE_NAME"] << " ." << std::endl;
    return EXIT_SUCCESS;
}
