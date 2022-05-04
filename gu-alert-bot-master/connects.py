import json
import sys
import time
from datetime import datetime, timedelta

from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTask
from thehive4py.query import *
#from clickhouse_driver import Client

from env import *

api = TheHiveApi(THEHIVE_URL, THEHIVE_API_TOKEN)


#def ch_connect():  # Make try/except
#    client = Client(secret_CH['ip'],
#                    port=secret_CH['port'],
#                    user=secret_CH['user'],
#                    password=secret_CH['password'],
#                    verify=False,
#                    database=secret_CH['db']
#                    )
#    return client


#def load_data_to_ch(parsed_data):
#    client = ch_connect()
#    # 'Регион: 03-GU\nТип атаки:\nScan.Generic.PortScan.UDP\nКолличество атак: 5\n
#    data = parsed_data.split('\n')
#
#    client.execute('INSERT INTO alerts (timestamp, region, name, event_count) VALUES',
#                   [(
#                       # (datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
#                       datetime.now() + timedelta(hours=3),
#                       data[0].split(': ')[1],
#                       data[2],
#                       int(data[3].split(': ')[1])
#                   )])
#
#    result, columns = client.execute('SELECT count(region) FROM alerts GROUP BY region', with_column_types=True)


def create_task(case_id, title, description):
    response = api.create_case_task(case_id, CaseTask(
        title=title,
        status='InProgress',
        owner='sc_bot',
        flag=False,
        description=description,
        startDate=int(time.time()) * 1000))

    return response
