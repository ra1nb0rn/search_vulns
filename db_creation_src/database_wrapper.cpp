#include "database_wrapper.h"


PreparedStatement* DatabaseWrapper::get_cve_query() {
    return cve_query.get();
}

PreparedStatement* DatabaseWrapper::get_cve_cpe_query() {
    return cve_cpe_query.get();
}

PreparedStatement* DatabaseWrapper::get_add_exploit_ref_query() {
    return add_exploit_ref_query.get();
}

PreparedStatement* DatabaseWrapper::get_add_cveid_exploit_ref_query() {
    return add_cveid_exploit_ref_query.get();
}


// ---------------------------------------------------------


SQLiteDB::SQLiteDB(const std::string& outfile) {
    db = std::make_unique<SQLite::Database>(outfile,  SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE);
}

void SQLiteDB::execute_query(std::string query) {
    db->exec(query);
}

void SQLiteDB::create_prepared_statements() {
    // init prepared statements
    cve_query =  std::make_unique<SQLitePreparedStatement>(*db, CVE_QUERY_FRAGMENT);
    cve_cpe_query =  std::make_unique<SQLitePreparedStatement>(*db, CVE_CPE_QUERY_FRAGMENT);
    add_exploit_ref_query =  std::make_unique<SQLitePreparedStatement>(*db, NVD_EXPLOIT_REFS_FRAGMENT);
    add_cveid_exploit_ref_query =  std::make_unique<SQLitePreparedStatement>(*db, CVE_NVD_EXPLOITS_REFS_FRAGMENT);
}

void SQLiteDB::commit() {
    transaction->commit();
}

void SQLiteDB::start_transaction() {
    transaction = std::make_unique<SQLite::Transaction>(*db);
}


// ---------------------------------------------------------


MariaDB::MariaDB(nlohmann::json config) {
    // Instantiate Driver
    sql::Driver* driver = sql::mariadb::get_driver_instance();

    // Configure Connection
    std::string host = config["DATABASE"]["HOST"];
    int port = config["DATABASE"]["PORT"];
    std::string user = config["DATABASE"]["USER"];
    std::string password = config["DATABASE"]["PASSWORD"];
    std::string database = config["DATABASE_NAME"];
    sql::SQLString url("jdbc:mariadb://" + host + ':' + std::to_string(port));
    sql::Properties properties({{"user", user}, {"password", password}});

    conn = std::unique_ptr<sql::Connection>(driver->connect(url, properties));
    
    std::string create_db_query = "CREATE OR REPLACE DATABASE "+database+";";
    std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
    stmnt->executeQuery(create_db_query);
    stmnt->executeQuery("use "+database+";");
}

void MariaDB::execute_query(std::string query) {
    std::unique_ptr<sql::Statement> stmnt(conn->createStatement());
    stmnt->executeQuery(query);
}

void MariaDB::create_prepared_statements() {
    // init prepared statements
    cve_query =  std::make_unique<MariaDBPreparedStatement>(conn, CVE_QUERY_FRAGMENT);
    cve_cpe_query =  std::make_unique<MariaDBPreparedStatement>(conn, CVE_CPE_QUERY_FRAGMENT);
    add_exploit_ref_query =  std::make_unique<MariaDBPreparedStatement>(conn, NVD_EXPLOIT_REFS_FRAGMENT);
    add_cveid_exploit_ref_query =  std::make_unique<MariaDBPreparedStatement>(conn, CVE_NVD_EXPLOITS_REFS_FRAGMENT);
}

void MariaDB::commit() {
    conn->commit();
}

void MariaDB::start_transaction() {
    conn->setAutoCommit(false);
}

void MariaDB::close_connection() {
    conn->close();
}