import sqlite3
import mariadb
import csv
import sys
import os

def export_tables_to_csv(database_file):
    # Connect to the SQLite database
    conn = sqlite3.connect(database_file)
    cursor = conn.cursor()

    # Get the list of tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    # Export each table to a separate CSV file
    for table in tables:
        table_name = table[0]
        csv_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"{table_name}.csv")
        cursor.execute(f"SELECT * FROM {table_name};")
        rows = cursor.fetchall()
        with open(csv_file, 'w', newline='\n') as file:
            writer = csv.writer(file, dialect='unix', escapechar='\\')
            writer.writerows(rows)
        print(f"Generated {table_name}.csv")

    # Close the database connection
    cursor.close()
    conn.close()
    

def export_tables_mariadb_to_csv(config):
    database_name, user, password, host, port = config.split(',')
    # Connect to the mariadb database
    conn = mariadb.connect(
        user=user,
        password=password,
        host=host,
        port=int(port),
        database=database_name
    )
    cursor = conn.cursor()

    # Get the list of tables in the database
    cursor.execute("SHOW TABLES;")
    tables = cursor.fetchall()

    # Export each table to a separate CSV file
    for table in tables:
        table_name = table[0]
        csv_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), f"{table_name}.csv.mariadb")
        cursor.execute(f"SELECT * FROM {table_name};")
        rows = cursor.fetchall()

        with open(csv_file, 'w', newline='\n') as file:
            writer = csv.writer(file, dialect='unix', escapechar='\\')
            writer.writerows(rows)
        print(f"Generated {table_name}.csv.mariadb")

    # Close the database connection
    cursor.close()
    conn.close()



if __name__ == '__main__':
    if sys.argv[1] == 'sqlite':
        export_tables_to_csv(sys.argv[2])
    else:
        export_tables_mariadb_to_csv(sys.argv[2])
