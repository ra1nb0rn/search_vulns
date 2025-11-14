#!/bin/bash

# set up arguments
if [[ $# != 3 ]]; then
    echo "usage: $0 <sqlite.db3> <mariadb.cnf> <mariadb_database>"
    exit 1
fi

SQLITE_DB=$1
MARIADB_CONFIG_FILE=$2
MARIADB_DB=$3
OUTPUT_DIR="$(dirname $MARIADB_CONFIG_FILE)/mariadb_migration"
SCHEMA_TABLES_FILE="$OUTPUT_DIR/schema_tables.sql"
SCHEMA_VIEWS_FILE="$OUTPUT_DIR/schema_views.sql"
if [[ -d $OUTPUT_DIR ]]; then
    echo "Directory for storing exported data must not exist: $OUTPUT_DIR"
    exit 1
fi
mkdir -p $OUTPUT_DIR

echo "[+] Exporting table and index schema..."
sqlite3 "$SQLITE_DB" <<EOF > "$SCHEMA_TABLES_FILE"
SELECT sql || ';' FROM sqlite_master 
WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql NOT NULL
UNION ALL
SELECT sql || ';' FROM sqlite_master
WHERE type='index' AND sql NOT NULL;
EOF

echo "[+] Exporting view definitions..."
sqlite3 "$SQLITE_DB" <<EOF > "$SCHEMA_VIEWS_FILE"
SELECT sql || ';' FROM sqlite_master
WHERE type='view' AND sql NOT NULL;
EOF

echo "[+] Getting list of views..."
views=$(sqlite3 "$SQLITE_DB" "SELECT name FROM sqlite_master WHERE type='view';")

echo "[+] Exporting tables to CSV..."
tables=$(sqlite3 "$SQLITE_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
for table in $tables; do
    # Skip views in CSV export loop
    if echo "$views" | grep -qx "$table"; then
        echo "Skipping view $table for CSV export."
        continue
    fi
    echo "Exporting $table to CSV..."
    sqlite3 -header -csv "$SQLITE_DB" "SELECT * FROM \"$table\";" > "$OUTPUT_DIR/$table.csv"
done

echo "[+] Importing tables and indexes into MariaDB..."
mysql --defaults-extra-file="$MARIADB_CONFIG_FILE" -e "DROP DATABASE IF EXISTS $MARIADB_DB; CREATE DATABASE $MARIADB_DB;"
mysql --defaults-extra-file="$MARIADB_CONFIG_FILE" "$MARIADB_DB" < "$SCHEMA_TABLES_FILE"

echo "[+] Loading CSV data into MariaDB..."
for csv_file in "$OUTPUT_DIR"/*.csv; do
    table_name=$(basename "$csv_file" .csv)
    # Skip views here also
    if echo "$views" | grep -qx "$table_name"; then
        echo "Skipping view $table_name for data import."
        continue
    fi
    echo "Importing data into $table_name..."
    mysql --defaults-extra-file="$MARIADB_CONFIG_FILE" --local-infile=1 "$MARIADB_DB" -e "
        LOAD DATA LOCAL INFILE '$csv_file' 
        INTO TABLE \`$table_name\` 
        FIELDS TERMINATED BY ',' ENCLOSED BY '\"' 
        LINES TERMINATED BY '\n' 
        IGNORE 1 LINES;"
done

echo "[+] Importing views into MariaDB..."
mysql --defaults-extra-file="$MARIADB_CONFIG_FILE" "$MARIADB_DB" < "$SCHEMA_VIEWS_FILE"

# clean up
rm -r $OUTPUT_DIR

echo "[+] Migration complete."
