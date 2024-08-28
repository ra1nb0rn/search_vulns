#include "prepared_statement.h"

MariaDBPreparedStatement::MariaDBPreparedStatement(std::unique_ptr<sql::Connection>& conn, const std::string& query) {
    statement = std::unique_ptr<sql::PreparedStatement>(conn->prepareStatement("INSERT IGNORE"+query));
}

void MariaDBPreparedStatement::bind(int index, std::string s) {
    statement->setString(index, s);
}

void MariaDBPreparedStatement::bind(int index, int i) {
    statement->setInt(index, i);
}

void MariaDBPreparedStatement::bind(int index, double d) {
    statement->setDouble(index, d);
}

void MariaDBPreparedStatement::bind(int index, bool b) {
    statement->setBoolean(index, b);
}

void MariaDBPreparedStatement::execute() {
    statement->executeUpdate();
}


SQLitePreparedStatement::SQLitePreparedStatement(SQLite::Database& db, const std::string& query) {
    statement = std::make_unique<SQLite::Statement>(db, "INSERT OR IGNORE" + query);
}

void SQLitePreparedStatement::bind(int index, std::string s) {
    statement->bind(index, s);
}

void SQLitePreparedStatement::bind(int index, int i) {
    statement->bind(index, i);
}

void SQLitePreparedStatement::bind(int index, double d) {
    statement->bind(index, d);
}

void SQLitePreparedStatement::bind(int index, bool b) {
    statement->bind(index, b);
}

void SQLitePreparedStatement::execute() {
    statement->exec();
    statement->reset();
}