#pragma once

#include <nlohmann/json.hpp>
#include "prepared_statement.h"

inline const std::string CVE_QUERY_FRAGMENT = " INTO nvd VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
inline const std::string CVE_CPE_QUERY_FRAGMENT = " INTO nvd_cpe VALUES (?, ?, ?, ?, ?, ?)";
inline const std::string NVD_EXPLOITS_REFS_FRAGMENT = " INTO nvd_exploits_refs VALUES (?, ?)";
inline const std::string NVD_EXPLOITS_REFS_INDIRECT_FRAGMENT = " INTO nvd_exploits_refs_indirect VALUES (?, ?)";


class DatabaseWrapper {
public:
    DatabaseWrapper() {}
    virtual void execute_query(std::string query) = 0;
    virtual void commit() = 0;
    virtual void start_transaction() = 0;
    virtual void close_connection() = 0;
    virtual void create_prepared_statements() = 0;
    PreparedStatement* get_cve_query();
    PreparedStatement* get_cve_cpe_query();
    PreparedStatement* get_add_nvd_exploits_ref_query();
    PreparedStatement* get_add_nvd_exploits_ref_indirect_query();
protected:
    std::unique_ptr<PreparedStatement> cve_query = nullptr;
    std::unique_ptr<PreparedStatement> cve_cpe_query = nullptr;
    std::unique_ptr<PreparedStatement> add_nvd_exploits_ref_query = nullptr;
    std::unique_ptr<PreparedStatement> add_nvd_exploits_ref_indirect_query = nullptr;
};

class SQLiteDB: public DatabaseWrapper {
public:
    SQLiteDB(const std::string& outfile);
    void execute_query(std::string query);
    void commit();
    void start_transaction();
    void close_connection() {}
    void create_prepared_statements();
private:
    std::unique_ptr<SQLite::Database> db;
    std::unique_ptr<SQLite::Transaction> transaction = nullptr;
};

class MariaDB: public DatabaseWrapper {
public:
    MariaDB(nlohmann::json config);
    void execute_query(std::string query);
    void commit();
    void start_transaction();
    void close_connection();
    void create_prepared_statements();
private:
    std::unique_ptr<sql::Connection> conn;
};