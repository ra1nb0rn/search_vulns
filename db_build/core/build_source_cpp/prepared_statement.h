#ifndef PREPARED_STATEMENT_H
#define PREPARED_STATEMENT_H

#include <string>
#include <SQLiteCpp/SQLiteCpp.h>
// include mariadb
#include <conncpp.hpp>


class PreparedStatement {
public:
    PreparedStatement() {}
    virtual ~PreparedStatement() {}
    virtual void bind(int index, std::string s) = 0;
    virtual void bind(int index, int i) = 0;
    virtual void bind(int index, double d) = 0;
    virtual void bind(int index, bool b) = 0;
    virtual void execute() = 0;
};

class SQLitePreparedStatement: public PreparedStatement{
public:
    SQLitePreparedStatement(SQLite::Database& db, const std::string& query);
    void bind(int index, std::string s);
    void bind(int index, int i);
    void bind(int index, double d);
    void bind(int index, bool b);
    void execute();
private:
    std::unique_ptr<SQLite::Statement> statement;
};

class MariaDBPreparedStatement: public PreparedStatement{
public:
    MariaDBPreparedStatement(std::unique_ptr<sql::Connection>& conn, const std::string& query);
    void bind(int index, std::string s);
    void bind(int index, int i);
    void bind(int index, double d);
    void bind(int index, bool b);
    void execute();
private:
    std::unique_ptr<sql::PreparedStatement> statement;
};


#endif //PREPARED_STATEMENT_H