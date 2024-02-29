#!/bin/bash

DATABASE_FILE=$(realpath "$1")
CPE_DATABASE_FILE=$(realpath "$2")
CONFIG_FILE=$(realpath "$3")

# init values from config file
ABS_PATH=$(realpath "$0")
ABS_PATH=$(dirname "$ABS_PATH")
HOST=$(jq -r '.DATABASE.HOST' $CONFIG_FILE)
USER=$(jq -r '.DATABASE.USER' $CONFIG_FILE)
PASSWORD=$(jq -r '.DATABASE.PASSWORD' $CONFIG_FILE)
PORT=$(jq -r '.DATABASE.PORT' $CONFIG_FILE)
DATABASE_NAME=$(jq -r '.DATABASE_NAME' $CONFIG_FILE)
CPE_DATABASE_NAME=$(jq -r '.cpe_search.DATABASE_NAME' $CONFIG_FILE)
CREATE_TABLES_QUERIES_VULNDB=$ABS_PATH/$(jq -r '.CREATE_SQL_STATEMENTS_FILE' $CONFIG_FILE)
CREATE_TABLES_QUERIES_CPE_SEARCH=$ABS_PATH/$(jq -r '.cpe_search.CREATE_SQL_STATEMENTS_FILE' $CONFIG_FILE)

add_vulndb_data() {
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL local_infile=1;"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/cve.csv' INTO TABLE cve FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/cve_cpe.csv' INTO TABLE cve_cpe FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/cve_nvd_exploits_refs.csv' INTO TABLE cve_nvd_exploits_refs FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/cve_poc_in_github_map.csv' INTO TABLE cve_poc_in_github_map FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/nvd_exploits_refs.csv' INTO TABLE nvd_exploits_refs FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL local_infile=0;"
}

add_cpe_search_data() {
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL local_infile=1;"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/cpe_entries.csv' INTO TABLE cpe_entries FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "LOAD DATA LOCAL INFILE '$ABS_PATH/terms_to_entries.csv' INTO TABLE terms_to_entries FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n';"
    mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL local_infile=0;"
}

perform_integrity_checks() {
    migration_successfull=0
    for file in $ABS_PATH/*.csv; do
        # Count the number of lines in the file
        line_count=$(wc -l < "$file")

        table_name=${file%.*}

        # Compare the line count with the entry count
        if [[ $(diff <(cat $file | sort) <(cat $file.mariadb| sort)) ]]; then
            echo "[-] $table_name mismatch"
            migration_successfull=1
        fi
    done

    # remove csv files
    rm $ABS_PATH/*.csv $ABS_PATH/*.csv.mariadb

    if [ $migration_successfull -eq 0 ]; then
        echo "[+] Migration successful"
        return 0
    else
        echo "[-] Migration failed"
        return 1
    fi
}

#################################
########## Entry point ##########
#################################

# check number of arguments
if [ "$#" -ne 3 ];then
    echo "[-] Numbers of arguments does not match"
    echo "[-] Usage: ./migrate_sqlite_to_mariadb.sh SQLITE_DB_PATH SQLITE_CPE_DB_PATH PATH_TO_CONFIG"
    exit 1
fi


# Export sqlite databases
echo "[+] Export sqlite as csv"
python3 $ABS_PATH/export_database_as_csv.py sqlite $DATABASE_FILE
python3 $ABS_PATH/export_database_as_csv.py sqlite $CPE_DATABASE_FILE

# Create databases
echo "[+] Add data to mariadb"
# get queries from file
vulndb_create_tables_queries=$(cat $CREATE_TABLES_QUERIES_VULNDB | jq '.TABLES | .[] | select(.mariadb) | .mariadb'| tr '\n' ' ' | sed 's/"//g')
cpe_search_create_tables_queries=$(cat $CREATE_TABLES_QUERIES_CPE_SEARCH | jq '.TABLES | .[] | select(.mariadb) | .mariadb' | tr '\n' ' ' | sed 's/"//g')
# create vulndb tables and add data
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL max_heap_table_size = 8589934592;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL tmp_table_size = 8589934592;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "$vulndb_create_tables_queries"
add_vulndb_data
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL max_heap_table_size = 16777216;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "SET GLOBAL tmp_table_size = 16777216;"
# create cpe_search tables and add data
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL max_heap_table_size = 8589934592;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL tmp_table_size = 8589934592;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "$cpe_search_create_tables_queries"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL max_heap_table_size = 16777216;"
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$CPE_DATABASE_NAME" -e "SET GLOBAL tmp_table_size = 16777216;"
add_cpe_search_data

# create views
vulndb_create_views=$(cat $CREATE_TABLES_QUERIES_VULNDB | jq '.VIEWS | .[] | select(.mariadb) | .mariadb'| tr '\n' ' ' | sed 's/"//g')
mariadb -u $USER --password=$PASSWORD -h $HOST -P $PORT -D "$DATABASE_NAME" -e "$vulndb_create_views"

# Export mariadb databases
echo "[+] Export mariadb as csv"
python3 $ABS_PATH/export_database_as_csv.py mariadb $DATABASE_NAME,$USER,$PASSWORD,$HOST,$PORT
python3 $ABS_PATH/export_database_as_csv.py mariadb $CPE_DATABASE_NAME,$USER,$PASSWORD,$HOST,$PORT

# check whether everything migrated correctly
# Loop through each CSV file in the current folder
echo "[+] Perform integrity checks"
perform_integrity_checks