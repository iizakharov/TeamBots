"""
Success
botId: 1000000026
nick: sc_alert_bot
token: 001.1670898373.4155924238:1000000026
"""
import schedule
import time

from bot.bot import Bot
import logging.config
from datetime import datetime, timedelta
from time import sleep
import re

# logging.config.fileConfig('log.ini')
from utils import get_new_alarms_kasper, get_new_alarms_mssec, get_all_attacks, get_stats, get_all_events, \
    get_stats_event, get_change_privilege_events, get_vpo_events
from env import DEBUG, BOT_TOKEN, API_BASE_URL, TEST_CHATS, TEST_BOT_TOKEN, CHAT_TO_ALERT

bot = Bot(token=BOT_TOKEN, api_url_base=API_BASE_URL)

if DEBUG:
    TIME_TO_ALERT = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
    MINUTES_TO = 59
    SCAN_PERIOD = 1
    chats_to_send_notifications = TEST_CHATS
    BOT_TOKEN = TEST_BOT_TOKEN
    bot = Bot(token=BOT_TOKEN, api_url_base=API_BASE_URL)

else:
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y.%m.%d %I:%M:%S %p',
                        level=logging.DEBUG)
    TIME_TO_ALERT = [7, 9, 12, 15, 17, 21]
    MINUTES_TO = 5
    SCAN_PERIOD = 5
    chats_to_send_notifications = CHAT_TO_ALERT


def send_alert(message):
    for chat in chats_to_send_notifications:
        msg = bot.send_text(chat_id=chat, text=message, parse_mode="MarkdownV2")
        if not msg.json()['ok']:
            message = message.replace("*__", "").replace("__*", "").replace("*", "")
            bot.send_text(chat_id=chat, text=message)


def main():
    message = ''
    kasper = get_new_alarms_kasper()
    mssec = get_new_alarms_mssec()
    now, table = datetime.now() + timedelta(hours=3), False

    if int(now.strftime("%H")) in TIME_TO_ALERT and int(now.strftime("%M")) < MINUTES_TO:
        table = get_all_attacks()
        sleep(0.3)
        top_events = get_all_events()
        sleep(0.3)
        groups_privilege = get_change_privilege_events()
        sleep(0.3)
        vpo = get_vpo_events()
        count_regions, count_attacks, count_sources, count_targets = get_stats()
        if not(count_regions == count_attacks == count_sources == count_targets == 0):
            message = f'*__Сводка событий безопасности на {now.strftime("%d.%m.%Y %H:%M")} за 24 часа:__*\n\n'

        if table:
            message += f"*События \"Сетевые атаки\":*\n" \
                       f"Учреждений с атаками: {count_regions}\n" \
                       f"Всего атак: {count_attacks}\n" \
                       f"Атакующих: {count_sources}\n" \
                       f"Атакованных: {count_targets}\n\n"
            for row in table:
                message += row + '\n'
        count_4624, count_4625, count_4627, region_count, arms_count = get_stats_event()
        message += f"\n*События 4625 (неуспешным входом в систему):*\n" \
                   f"Учреждений : {region_count}\n" \
                   f"АРМов: {arms_count}\n" \
                   f"Событий с кодом 4625: {count_4625}\n\n"
                   # f"Событий с кодом 4624: {count_4624}\n" \
                   # f"Событий с кодом 4627: {count_4627}\n\n"
        for row in top_events:
            message += row + '\n'
        if vpo:
            message += f"\n*События \"Обнаружен вредоносный объект\":*"
            for gu, data in vpo.items():
                message += f'\n*Регион: {gu}*\n'
                for _ip in data:
                    try:
                        for ip, hostnames in _ip.items():
                            for hostname in hostnames:
                                for hn, vpos in hostname.items():
                                    count_vpos = "".join(vpos) if len(vpos) == 1 else len(vpos)
                                    message += f'АРМ: {hn} ({ip})\n' \
                                               f'Обнаружено ВПО: {str(count_vpos) + " видов(а)" if isinstance(count_vpos, int) else count_vpos}\n'
                    except Exception as e:
                        print(e)
        if groups_privilege:
            user_name_reg = re.compile(r'[Cc][Nn]=([\w\s\.\-\_]+)')
            message += f"\n\n*События \"Изменение привилегий\":*"
            for gu, data in groups_privilege.items():
                message += f'\n*Регион: {gu}*'
                for item in data:
                    state = None
                    if item[1] == 4728:
                        state = "Добавление пользователя"
                    elif item[1] == 4729:
                        state = "Удаление пользователя"
                    elif item[1] == 4727:
                        state = "Создана группа с поддержкой безопасности"
                    elif item[1] == 4730:
                        state = "Группа с поддержкой безопасности удалена"
                    message += f'\n{item[0].replace("T", " ")}: {item[1]} ({state if state else item[2]})\n' \
                               f'Кто: {item[4]}\n' \
                               f'Кого: {re.search(user_name_reg, item[6]).group(1)}\n' \
                               f'Группа: {item[5]}\n\n'
        send_alert(message)
        time.sleep(1)
        if int(now.strftime("%H")) == 9:
            send_alert('/statat')
    if kasper:
        for item in kasper:
            text_to_send = f"{'*'*30}" \
                           f"{item[1]}!\n\n" \
                           f"{item[7]}\n" \
                           f"Время: {str(item[0]).replace('T', ' ')}\n" \
                           f"Атакующий: {item[2]}\n" \
                           f"Атакуемый: {item[3]} ({item[8]})\n" \
                           f"Порт: {item[4]} ({item[5]})\n" \
                           f"Имя атакуемого: {item[6]}\n"
            send_alert(text_to_send)
            time.sleep(1)
    if mssec:
        for item in mssec:
            text_to_send = f"{'*'*30}" \
                           f"Обнаружен зараженный АРМ!\n\n" \
                           f"{item[1]}\n" \
                           f"Время: {str(item[0]).replace('T', ' ')}\n" \
                           f"Имя АРМ: {item[2]}\n" \
                           f"IP-адрес: {item[3]}\n" \
                           f"Признак заражения: {item[7]}\n" \
                           f"Статус АВЗ: {'Установленно' if item[8] == 'True' else 'Не установлено'}\n" \
                           f"Статус СЗИ: {'Установленно' if item[9] == 'True' else 'Не установлено'}"
            send_alert(text_to_send)
            time.sleep(1)
    else:
        return


if DEBUG:
    if __name__ == '__main__':
        main()
# schedule.every().day.at("09:15").do(send_alert)
else:
    schedule.every(SCAN_PERIOD).minutes.do(main)
    while True:
        schedule.run_pending()
        time.sleep(1)
