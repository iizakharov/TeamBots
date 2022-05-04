import os

import schedule
import time

from bot.bot import Bot
import logging.config
from datetime import datetime, timedelta

from env import TOP, CHATS, ATTACKS_CASE_ID, LOGON_FAILURE_CASE_ID, TOKEN
from utils import get_all_attacks, get_all_events, get_tenant_attacks, get_gu_ad_stat, get_time_to_send,\
    exception_print, time_to_alarm, make_files
from connects import create_task

# logging.config.fileConfig('log.ini')
# logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
#                     datefmt='%Y.%m.%d %I:%M:%S %p', level=logging.DEBUG)

bot = Bot(token=TOKEN, api_url_base='https://api.digital.gov.ru/bot/v1')
chat_dict = CHATS


def main():
    now = datetime.now()
    except_gu = []
    to_send = []
    attacks, attacks_by_tenants = get_all_attacks()
    top_events = get_all_events()
    if attacks_by_tenants:
        other_events = []
        for tenant, events in attacks_by_tenants.items():
            flag = True
            for reg, val in chat_dict.items():
                if val[-1].upper() in str(tenant).upper():
                    flag = False
                    chat_id = val[0]
                    timezone = val[1]
                    if get_time_to_send(timezone):
                        data = {
                            'fieldnames': ['Дата', 'Регион', 'Учреждение', 'Источник', 'Цель', 'Целевой порт', 'Угроза'],
                            'source': events
                        }
                        to_send.append(reg)
                        file_csv, file_xls = make_files(data, 'attacks', reg)
                        bot.send_text(chat_id=chat_id, text='С ваших адресов поступают сетевые атаки')
                        with open(file_csv, 'r') as file:
                            bot.send_file(chat_id=chat_id, file=file, caption='CSV Сводка по сетевым атакам')
                        with open(file_xls, 'r+b') as file:
                            bot.send_file(chat_id=chat_id, file=file, caption='XLS Сводка по сетевым атакам')
                        os.remove(file_csv)
                        os.remove(file_xls)
            if flag:
                other_events += events
        if other_events:
            chat_id = "ApFjHd6JU-7WiVE"  # "AoprZKyuaQ_prms"
            if get_time_to_send(0):
                data = {
                    'fieldnames': ['Дата', 'Регион', 'Учреждение', 'Источник', 'Цель', 'Целевой порт', 'Угроза'],
                    'source': other_events
                }
                to_send.append("SC-ALERTS")
                file_csv, file_xls = make_files(data, 'attacks', 'other')
                bot.send_text(chat_id=chat_id, text='Неразобранные адреса, с которых поступают сетевые атаки.')
                with open(file_csv, 'r') as file:
                    bot.send_file(chat_id=chat_id, file=file, caption='CSV Сводка по сетевым атакам')
                with open(file_xls, 'r+b') as file:
                    bot.send_file(chat_id=chat_id, file=file, caption='XLS Сводка по сетевым атакам')
                os.remove(file_csv)
                os.remove(file_xls)

    # for attack in attacks:
    #     message = 'Уведомление о сетевых атаках за последние 24 часа: \n\n'
    #     region = str(attack).split('\n')[0].split(': ')[1]
    #     for reg in chat_dict.keys():
    #         if reg in region.upper():
    #             chat_id = chat_dict[reg][0]
    #             timezone = chat_dict[reg][1]
    #             message += attack
    #             if get_time_to_send(timezone):
    #                 file_csv, file_xls = get_tenant_attacks(region, top=TOP)
    #                 bot.send_text(chat_id=chat_id, text=message)
    #                 to_send.append(reg)
    #                 with open(file_csv, 'r') as file:
    #                     bot.send_file(chat_id=chat_id, file=file, caption='CSV Сводка по сетевым атакам')
    #                 with open(file_xls, 'r+b') as file:
    #                     bot.send_file(chat_id=chat_id, file=file, caption='XLS Сводка по сетевым атакам')
    #                 os.remove(file_csv)
    #                 os.remove(file_xls)
    #             else:
    #                 except_gu.append(reg)
    #             break

    for event in top_events:
        message = 'Уведомление о событиях "неуспешный вход в систему" за последние 24 часа: \n\n'
        count_events = str(event).split('\n')[1].split(': ')[1]
        if int(count_events) < 100:
            continue
        region = str(event).split('\n')[0].split(': ')[1]
        for reg in chat_dict.keys():
            if reg in region.upper():
                chat_id = chat_dict[reg][0]
                timezone = chat_dict[reg][1]
                message += event
                if get_time_to_send(timezone):
                    f_name_csv, f_name_xls = get_gu_ad_stat(region)
                    bot.send_text(chat_id=chat_id, text=message)
                    to_send.append(reg)
                    with open(f_name_csv, 'r') as file:
                        caption = 'CSV Сводка по неуспешным входам по учреждению: ' + region
                        bot.send_file(chat_id=chat_id, file=file, caption=caption)
                    with open(f_name_xls, 'r+b') as file:
                        caption = 'XLS Сводка по неуспешным входам по учреждению: ' + region
                        bot.send_file(chat_id=chat_id, file=file, caption=caption)
                    os.remove(f_name_csv)
                    os.remove(f_name_xls)
                else:
                    except_gu.append(reg)
    if to_send:
        to_send = list(set(to_send))
        bot.send_text(chat_id="i.zaharov@mchs.gov.ru",
                      text='Отправил отчет в {0} брат {1}{2}'.format(", ".join(to_send), u"\U0001F52B", u"\U0001F60E"))

# if __name__ == '__main__':
#     main()
schedule.every(1).hours.do(main)
# schedule.every(1).minutes.do(main)
# # schedule.every().day.at("07:00").do(main)
while True:
    schedule.run_pending()
    time.sleep(1)

