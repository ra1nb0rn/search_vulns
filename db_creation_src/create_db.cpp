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
    PreparedStatement* add_exploit_ref_query = db->get_add_exploit_ref_query();
    PreparedStatement* add_cveid_exploit_ref_query = db->get_add_cveid_exploit_ref_query(); 

    // read a JSON file
    std::ifstream input_file(filepath);
    json j;
    input_file >> j;

    json metrics_entry, metrics_type_entry, references_entry;
    std::string cve_id, description, edb_ids, published, last_modified, vector_string, severity;
    std::string cvss_version, ref_url, op;
    std::unordered_map<std::string, int> nvd_exploits_refs;
    std::unordered_map<std::string, std::unordered_set<int>> cveid_exploits_map;
    std::size_t datetime_dot_pos;
    bool vulnerable;
    double base_score;
    int cur_node_id;

    // iterate the array
    for (auto &cve_entry : j["vulnerabilities"]) {
        cve_id = cve_entry["cve"]["id"];
        edb_ids = "";

        // first retrieve data about CVE and put it into DB
        description = "N/A";
        for (auto &desc_entry : cve_entry["cve"]["descriptions"]) {
            if (desc_entry["lang"] == "en") {
                description = desc_entry["value"];
                break;
            }
        }

        // cvss metrics_entry_type (2, 3.0, 3.1)
        metrics_entry = cve_entry["cve"]["metrics"];
        if (metrics_entry.find("cvssMetricV31") != metrics_entry.end()) {
            metrics_type_entry = metrics_entry["cvssMetricV31"];
        }
        else if (metrics_entry.find("cvssMetricV30") != metrics_entry.end()) {
            metrics_type_entry = metrics_entry["cvssMetricV30"];
        }
        else if (metrics_entry.find("cvssMetricV2") != metrics_entry.end()) {
            metrics_type_entry = metrics_entry["cvssMetricV2"];
        }

        // get base_score, severity, cvss_version and vector
        if (metrics_type_entry != NULL){
            for (auto &metric : metrics_type_entry){
                // assume there's always a Primary entry
                if (metric["type"] == "Primary") {
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
        else {
            base_score = -1;
            vector_string = "";
            cvss_version = "";
            severity = "";
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
                            std::unordered_set<int> exploit_refs;
                            cveid_exploits_map[cve_id] = exploit_refs;
                        }
                        cveid_exploits_map[cve_id].emplace(nvd_exploits_refs[ref_url]);
                    }
                }
            }
        }

        // bind found cve info to prepared statement
        cve_query->bind(1, cve_id);
        cve_query->bind(2, description);
        cve_query->bind(3, edb_ids);
        cve_query->bind(4, published);
        cve_query->bind(5, last_modified);
        
        // Assumption: every entry has at least a cvssV2 score
        cve_query->bind(6, cvss_version);
        cve_query->bind(7, base_score);
        cve_query->bind(8, vector_string);
        cve_query->bind(9, severity);
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
            for (auto &config_nodes_entry : cve_config_entry["nodes"]) {
                std::vector<VagueCpeInfo> node_vulnerable_cpes;

                if (config_nodes_entry.find("cpeMatch") != config_nodes_entry.end()) {
                    for (auto &cpe_entry : config_nodes_entry["cpeMatch"]) {
                        vague_cpe_info = {cpe_entry["criteria"], "", "", "", ""};

                        if (!cpe_entry["vulnerable"])
                            continue;

                        if (cpe_entry.find("versionStartIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartIncluding"];
                            vague_cpe_info.version_start_type = "Including";
                        }
                        else if (cpe_entry.find("versionStartExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_start = cpe_entry["versionStartExcluding"];
                            vague_cpe_info.version_start_type = "Excluding";
                        }

                        if (cpe_entry.find("versionEndIncluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndIncluding"];
                            vague_cpe_info.version_end_type = "Including";
                        }
                        else if (cpe_entry.find("versionEndExcluding") != cpe_entry.end()) {
                            vague_cpe_info.version_end = cpe_entry["versionEndExcluding"];
                            vague_cpe_info.version_end_type = "Excluding";
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
        add_exploit_ref_query->bind(1, exploit.second);
        add_exploit_ref_query->bind(2, exploit.first);
        add_exploit_ref_query->execute();
    }

    // Put CVEs to NVD exploit refs into DB
    for (auto &mapping_entry : cveid_exploits_map) {
        for (auto &ref_id : mapping_entry.second) {
            add_cveid_exploit_ref_query->bind(1, mapping_entry.first);
            add_cveid_exploit_ref_query->bind(2, ref_id);
            add_cveid_exploit_ref_query->execute();
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

    if (argc != 5) {
        std::cerr << "Wrong argument count." << std::endl;
        std::cerr << "Usage: ./create_db cve_folder path_to_config outfile create_sql_statements_file" << std::endl;
        return EXIT_FAILURE;
    }

    std::string cve_folder = argv[1];
    std::ifstream config_file(argv[2]);
    json config = json::parse(config_file);
    std::string outfile = argv[3];
    std::ifstream create_sql_statements_file(argv[4]);
    json create_sql_statements = json::parse(create_sql_statements_file);
    std::string database_type = config["DATABASE"]["TYPE"];
    std::string filename;
    std::vector<std::string> cve_files;

    auto start_time = std::chrono::high_resolution_clock::now();
    
    std::unique_ptr<DatabaseWrapper> db;

    // validate given database name
    if (database_type != "sqlite" && !is_safe_database_name(config["DATABASE_NAME"])) {
        std::cout << "Potentially malicious database name detected. Abort creation of database" << std::endl;
        return EXIT_FAILURE;
    }

    try{
        // create database connection
        if (database_type == "sqlite")
            db = std::make_unique<SQLiteDB>(outfile);
        else{
            db = std::make_unique<MariaDB>(config);
        } 

        // create tables and prepared statements
        db->execute_query(create_sql_statements["TABLES"]["CVE"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["CVE_CPE"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["CVE_NVD_EXPLOITS_REFS"][database_type]);
        db->execute_query(create_sql_statements["TABLES"]["NVD_EXPLOITS_REFS"][database_type]);
        db->create_prepared_statements();

        DIR *dir;
        struct dirent *ent;
        if ((dir = opendir(cve_folder.c_str())) != NULL) {
            while ((ent = readdir(dir)) != NULL) {
                filename = ent->d_name;
                if (ends_with(filename, ".json"))
                    cve_files.push_back(cve_folder + "/" + filename);  // only on unix platforms
            }
            closedir(dir);
        }
        else {
            // could not open directory
            std::cerr << "Could not open directory \'" << cve_folder << "\'" << std::endl;
            return EXIT_FAILURE;
        }
        
        std::cout << "Creating local copy of NVD as " << outfile << " ..." << std::endl;
        for (const auto &file : cve_files) {
            add_to_db(db.get(), file);
        }

        // create view for nvd_exploits_refs
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

    char *db_abs_path = realpath(outfile.c_str(), NULL);
    std::cout << "Database creation took " <<
    (float) (std::chrono::duration_cast<std::chrono::microseconds>(time).count()) / (1e6) << "s .\n";
    std::cout << "Local copy of NVD created as " << db_abs_path << " ." << std::endl;
    free(db_abs_path);
    return EXIT_SUCCESS;

}
