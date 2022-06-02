#include <SQLiteCpp/SQLiteCpp.h>
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

void handle_exception(SQLite::Exception &e) {
    std::string msg = e.what();
    if (msg.find("UNIQUE constraint failed") == std::string::npos) {
        throw e;
    }
}

int add_to_db(SQLite::Database &db, const std::string &filepath) {
    // Begin transaction
    SQLite::Transaction transaction(db);
    SQLite::Statement cve_query(db, "INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    SQLite::Statement cve_cpe_query(db, "INSERT INTO cve_cpe VALUES (?, ?, ?, ?, ?, ?, ?)");
    SQLite::Statement add_exploit_ref_query(db, "INSERT INTO nvd_exploits_refs VALUES (?, ?)");
    SQLite::Statement add_cveid_exploit_ref_query(db, "INSERT INTO cve_nvd_exploits_refs VALUES (?, ?)");

    // read a JSON file
    std::ifstream input_file(filepath);
    json j;
    input_file >> j;

    json impact_entry, references_entry;
    std::string cve_id, description, edb_ids, published, last_modified, vector_string, severity, cvss_version, descr_line, ref_url;
    std::unordered_map<std::string, int> nvd_exploits_refs;
    std::unordered_map<std::string, std::unordered_set<int>> cveid_exploits_map;
    bool vulnerable;
    double base_score;

    // iterate the array
    for (auto &cve_entry : j["CVE_Items"]) {
        cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"];
        edb_ids = "";

        // first retrieve data about CVE and put it into DB
        // assume English as description language
        description = "";
        for (auto &desc_entry : cve_entry["cve"]["description"]["description_data"]) {
            descr_line = desc_entry["value"];
            description += descr_line + "\n";
        }
        if (description != "")
            description.pop_back();

        impact_entry = cve_entry["impact"];
        if (impact_entry.find("baseMetricV3") != impact_entry.end()) {
            base_score = (impact_entry["baseMetricV3"]["cvssV3"]["baseScore"]);
            vector_string = impact_entry["baseMetricV3"]["cvssV3"]["vectorString"];
            severity = impact_entry["baseMetricV3"]["cvssV3"]["baseSeverity"];
            cvss_version = impact_entry["baseMetricV3"]["cvssV3"]["version"];
        }
        else if (impact_entry.find("baseMetricV2") != impact_entry.end()) {
            base_score = impact_entry["baseMetricV2"]["cvssV2"]["baseScore"];
            vector_string = impact_entry["baseMetricV2"]["cvssV2"]["vectorString"];
            cvss_version = impact_entry["baseMetricV2"]["cvssV2"]["version"];
            severity = impact_entry["baseMetricV2"]["severity"];
        }
        else {
            base_score = -1;
            vector_string = "";
            cvss_version = "";
            severity = "";
        }
        published = cve_entry["publishedDate"];
        std::replace(published.begin(), published.end(), 'T', ' ');
        std::replace(published.begin(), published.end(), 'Z', ':');
        published += "00";
        last_modified = cve_entry["lastModifiedDate"];
        std::replace(last_modified.begin(), last_modified.end(), 'T', ' ');
        std::replace(last_modified.begin(), last_modified.end(), 'Z', ':');
        last_modified += "00";

        references_entry = cve_entry["cve"]["references"];
        if (references_entry.find("reference_data") != references_entry.end()) {
            for (auto &ref_entry : references_entry["reference_data"]) {
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
        }

        cve_query.bind(1, cve_id);
        cve_query.bind(2, description);
        cve_query.bind(3, edb_ids);
        cve_query.bind(4, published);
        cve_query.bind(5, last_modified);
        
        // Assumption: every entry has at least a cvssV2 score
        cve_query.bind(6, cvss_version);
        cve_query.bind(7, base_score);
        cve_query.bind(8, vector_string);
        cve_query.bind(9, severity);

        cve_query.exec();
        cve_query.reset();

        // Next, retrieve CPE data and put into DB  
        cve_cpe_query.bind(1, cve_id);
        VagueCpeInfo vague_cpe_info;

        for (auto &config_nodes_entry : cve_entry["configurations"]["nodes"]) {
            // assumption: either cpe_match.empty() or children.empty()

            // if there are specific CPEs listed
            if ((config_nodes_entry.find("cpe_match") != config_nodes_entry.end()) &&
                    !config_nodes_entry["cpe_match"].empty()) {

                if (config_nodes_entry.find("children") != config_nodes_entry.end() && !config_nodes_entry["children"].empty())
                    std::cerr << "Cannot parse CVE " << cve_id << " properly b/c cpe_match and children are not empty." << std::endl;

                for (auto &cpe_entry : config_nodes_entry["cpe_match"]) {
                    vulnerable = cpe_entry["vulnerable"];
                    if (!vulnerable)
                        continue;

                    vague_cpe_info = {cpe_entry["cpe23Uri"], "", "", "", ""};

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

                    cve_cpe_query.bind(2, vague_cpe_info.vague_cpe);
                    cve_cpe_query.bind(3, vague_cpe_info.version_start);
                    if (vague_cpe_info.version_start_type == "Including")
                        cve_cpe_query.bind(4, true);
                    else
                        cve_cpe_query.bind(4, false);
                    cve_cpe_query.bind(5, vague_cpe_info.version_end);
                    if (vague_cpe_info.version_end_type == "Including")
                        cve_cpe_query.bind(6, true);
                    else
                        cve_cpe_query.bind(6, false);
                    cve_cpe_query.bind(7, "");

                    try {
                        cve_cpe_query.exec();
                    }
                    catch (SQLite::Exception& e) {
                        handle_exception(e);
                    }

                    try {
                        cve_cpe_query.reset();
                    }
                    catch (SQLite::Exception& e) {
                        handle_exception(e);
                    }
                }
            }
            // otherwise if CPE data with version start and end is available
            else if (config_nodes_entry.find("children") != config_nodes_entry.end() &&
                    !config_nodes_entry["children"].empty()) {

                if (config_nodes_entry.find("operator") == config_nodes_entry.end()) {
                    std::cerr << "Cannot parse CVE " << cve_id << " properly. No operator." << std::endl;
                    continue;
                }
                else if (config_nodes_entry["operator"] != "AND" && config_nodes_entry["operator"] != "OR") {
                    std::cerr << "Cannot parse CVE " << cve_id << " properly. Unknown operator." << std::endl;
                    continue;
                }

                std::vector<std::unordered_set<VagueCpeInfo>> all_vulnerable_vague_cpes;
                std::vector<std::unordered_set<VagueCpeInfo>> all_children_cpes;

                for (auto &children_entry : config_nodes_entry["children"]) {
                    std::unordered_set<VagueCpeInfo> vulnerable_vague_cpes, children_cpes;

                    for (auto &cpe_entry : children_entry["cpe_match"]) {
                        VagueCpeInfo vague_cpe_info = {cpe_entry["cpe23Uri"], "", "", "", ""};

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

                        if (cpe_entry["vulnerable"])
                            vulnerable_vague_cpes.emplace(vague_cpe_info);

                        children_cpes.emplace(vague_cpe_info);
                    }
                    all_vulnerable_vague_cpes.push_back(vulnerable_vague_cpes);
                    all_children_cpes.push_back(children_cpes);
                }

                std::string vulnerable_with_str = "";
                int cur_vuln_children_group_idx = 0, cur_with_children_group_idx = 0;
                for (auto &vuln_child_group : all_vulnerable_vague_cpes) {
                    std::string vulnerable_with_str = "";
                    cur_with_children_group_idx = 0;

                    for (auto &with_child_group : all_children_cpes) {
                        if (cur_vuln_children_group_idx == cur_with_children_group_idx) {
                            cur_with_children_group_idx++;
                            continue;
                        }

                        for (auto &vulnerable_with_cpe : with_child_group) {
                            vulnerable_with_str += vulnerable_with_cpe.vague_cpe + ",";
                        }
                        cur_with_children_group_idx++;
                    }

                    if (vulnerable_with_str != "")
                        vulnerable_with_str.pop_back();

                    for (auto &vulnerable_cpe : vuln_child_group) {
                        cve_cpe_query.bind(2, vulnerable_cpe.vague_cpe);
                        if (vulnerable_cpe.version_start_type == "Including")
                            cve_cpe_query.bind(4, true);
                        else
                            cve_cpe_query.bind(4, false);
                        cve_cpe_query.bind(5, vulnerable_cpe.version_end);
                        if (vulnerable_cpe.version_end_type == "Including")
                            cve_cpe_query.bind(6, true);
                        else
                            cve_cpe_query.bind(6, false);
                        cve_cpe_query.bind(6, vulnerable_cpe.version_end_type);
                        cve_cpe_query.bind(7, vulnerable_with_str);

                        try {
                            cve_cpe_query.exec();
                        }
                        catch (SQLite::Exception& e) {
                            handle_exception(e);
                        }

                        try {
                            cve_cpe_query.reset();
                        }
                        catch (SQLite::Exception& e) {
                        }
                    }

                    cur_vuln_children_group_idx++;
                }
            }
        }
    }

    // Put exploit references into DB
    for (auto &exploit : nvd_exploits_refs) {
        add_exploit_ref_query.bind(1, exploit.second);
        add_exploit_ref_query.bind(2, exploit.first);
        add_exploit_ref_query.exec();
        add_exploit_ref_query.reset();
    }

    // Put CVEs to NVD exploit refs into DB
    for (auto &mapping_entry : cveid_exploits_map) {
        for (auto &ref_id : mapping_entry.second) {
            add_cveid_exploit_ref_query.bind(1, mapping_entry.first);
            add_cveid_exploit_ref_query.bind(2, ref_id);
            add_cveid_exploit_ref_query.exec();
            add_cveid_exploit_ref_query.reset();
        }
    }

    // Commit transaction
    transaction.commit();
    return 1;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 0 == str.compare(str.size()-suffix.size(), suffix.size(), suffix);
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cerr << "Wrong argument count." << std::endl;
        std::cerr << "Usage: ./create_db cve_folder outfile" << std::endl;
        return EXIT_FAILURE;
    }

    std::string cve_folder = argv[1];
    std::string outfile = argv[2];
    std::string filename;
    std::vector<std::string> cve_files;


    auto start_time = std::chrono::high_resolution_clock::now();
    try {
        SQLite::Database db(outfile, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE);

        db.exec("DROP TABLE IF EXISTS cve");
        db.exec("DROP TABLE IF EXISTS cve_cpe");
        db.exec("DROP TABLE IF EXISTS nvd_exploits_refs");
        db.exec("DROP TABLE IF EXISTS cve_nvd_exploits_refs");

        db.exec("CREATE TABLE cve (cve_id VARCHAR(25), description TEXT, edb_ids TEXT, published DATETIME, last_modified DATETIME, \
            cvss_version CHAR(3), base_score CHAR(3), vector VARCHAR(60), severity VARCHAR(15), PRIMARY KEY(cve_id))");
        db.exec("CREATE TABLE cve_cpe (cve_id VARCHAR(25), cpe TEXT, cpe_version_start VARCHAR(255), is_cpe_version_start_including BOOL, \
            cpe_version_end VARCHAR(255), is_cpe_version_end_including BOOL, with_cpes TEXT, PRIMARY KEY(cve_id, cpe, cpe_version_start, \
            is_cpe_version_start_including, cpe_version_end, is_cpe_version_end_including, with_cpes))");
        db.exec("CREATE TABLE nvd_exploits_refs (ref_id INTEGER, exploit_ref text, PRIMARY KEY (ref_id))");
        db.exec("CREATE TABLE cve_nvd_exploits_refs (cve_id VARCHAR(25), ref_id INTEGER, PRIMARY KEY (cve_id, ref_id))");


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
            add_to_db(db, file);
        }
    }
    catch (std::exception& e) {
        std::cerr << "exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    auto time = std::chrono::high_resolution_clock::now() - start_time;

    char *db_abs_path = realpath(outfile.c_str(), NULL);
    std::cout << "Database creation took " <<
    (float) (std::chrono::duration_cast<std::chrono::microseconds>(time).count()) / (1e6) << "s .\n";
    std::cout << "Local copy of NVD created as " << db_abs_path << " ." << std::endl;
    free(db_abs_path);
    return EXIT_SUCCESS;
}
