import csv
import sqlite3
import datetime


conn = sqlite3.connect('events.db', check_same_thread=False)
cursor = conn.cursor()
date = datetime.datetime.today()
month = date.strftime('%B %Y')


def create_table(table, mssec=False):
    if mssec:
        cursor.execute(f"""CREATE TABLE IF NOT EXISTS {table}
                               (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                               tenant TEXT NOT NULL, 
                               hostname TEXT NOT NULL,
                               local_address TEXT NOT NULL,
                               remote_address TEXT NOT NULL,
                               remote_port TEXT ,
                               state TEXT,
                               name TEXT,
                               avz_install TEXT,
                               szi_install TEXT,
                               date TEXT NOT NULL,
                               is_new INT)"""
                       )
    else:
        cursor.execute(f"""CREATE TABLE IF NOT EXISTS {table}
                       (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                       alert TEXT NOT NULL, 
                       attack_source_ip TEXT NOT NULL,
                       attack_target_ip TEXT NOT NULL,
                       port TEXT NOT NULL,
                       protocol TEXT ,
                       syslog_hostname TEXT,
                       event TEXT,
                       region TEXT,
                       date TEXT NOT NULL,
                       is_new INT)"""
                       )
    print(f'table {table} created!')
    return


def drop_table(table):
    cursor.execute(f"""DROP TABLE {table}""")
    print(f'table {table} removed!')


def get_ips(table):
    statement = f"SELECT * FROM {table}"
    cursor.execute(statement)
    result = cursor.fetchall()
    return result


def add_item(data, table, mssec=False):
    if mssec:
        statement = f"INSERT INTO {table} (date, tenant, hostname, local_address, remote_address, remote_port," \
                    f" state, name, avz_install, szi_install, is_new) " \
                    f"VALUES ('{data[0]}', '{data[1]}', '{data[2]}', '{data[3]}', '{data[4]}', '{data[5]}'," \
                    f" '{data[6]}', '{data[7]}', '{data[8]}', '{data[9]}', '1')"
    else:
        statement = f"INSERT INTO {table} (date, alert, attack_source_ip, attack_target_ip, port," \
                    f" protocol, syslog_hostname, event, region, is_new) " \
                    f"VALUES ('{data[0]}', '{data[1]}', '{data[2]}'," \
                    f" '{data[3]}', '{data[4]}', '{data[5]}', '{data[6]}', '{data[7]}', '{data[8]}', '1')"
    cursor.execute(statement)
    conn.commit()
    return


def set_all_old(table):
    sql = f"""UPDATE {table} SET is_new = 0"""
    cursor.execute(sql)


def check_one(data, table, mssec=False):
    date = data[0]
    if mssec:
        rows = cursor.execute(
            f"SELECT * FROM {table} WHERE date = ? AND remote_address = ?",
            (date, data[4]),
        ).fetchall()
    else:
        rows = cursor.execute(
            f"SELECT * FROM {table} WHERE date = ?",
            (date,),
        ).fetchall()
    return rows


if __name__ == "__main__":
    table = 'sc_events'
    # drop_table(table)
    # create_table(table)
    table = 'sc_events_mssec'
    # drop_table(table)
    # create_table(table, mssec=True)
    # set_all_old(table)
    data = get_ips(table)

    for row in data:
        print(row)
    # row = ['2021-10-15T02:45:18', 'Обнаружена сетевая атака', '162.214.103.159', '92.124.220.115', '1097', 'UDP', 'pso-psch3-a01', 'Scan.Generic.PortScan.UDP']
    # if check_one(row, table):
    #     print(True)
    # else:
    #     print(False)


