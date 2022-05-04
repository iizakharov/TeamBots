import os
from datetime import datetime, timedelta

home_menu = [
  [{"text": "Информация", "callbackData": "call_back_information"}],
  [{"text": "Контакты", "callbackData": "call_back_contacts"}],
  [{"text": "Инструкции", "callbackData": "call_back_instructions"}],
  [{"text": "Термины и определения", "callbackData": "call_back_terms"}],
  [{"text": "Сообщить об инциденте", "callbackData": "call_back_url"}]
]

instruction_menu = [
    [{"text": "Фишинг", "callbackData": "call_back_fishing"}],
    [{"text": "Сетевые атаки", "callbackData": "call_back_network_attacks"}],
    [{"text": "Вирусное заражение", "callbackData": "call_back_vpo"}],
    # [{"text": "САВЗ критический", "callbackData": "call_back_savz_stat_critical"}],
    # [{"text": "Доступ без МИ", "callbackData": "call_back_without_mi"}],
    # [{"text": "Назад", "callbackData": "call_back_back", "style": "primary"}],
    [{"text": "На главную", "callbackData": "call_back_home", "style": "primary"}]
]

button_home = [
    [{"text": "На главную", "callbackData": "call_back_home", "style": "primary"}]
]

instruction_menu = [
    [{"text": "Фишинг", "callbackData": "call_back_fishing"}],
    [{"text": "Сетевые атаки", "callbackData": "call_back_network_attacks"}],
    [{"text": "Вирусное заражение", "callbackData": "call_back_vpo"}],
    [{"text": "На главную", "callbackData": "call_back_home", "style": "primary"}],
]

callback_dict = {
    "call_back_information": "Информация",
    "call_back_contacts": "Контакты",
    "call_back_instructions": "Инструкции",
    "call_back_terms": "Термины и определения",
    "call_back_url": "Сообщить об инциденте",
    "call_back_fishing": "Фишинг",
    "call_back_network_attacks": "Сетевые атаки",
    "call_back_vpo": "Вирусное заражение",
    "call_back_home": "На главную",
}

allowed_chats = [
    '',
]

admins = [
    '',
]


def try_send(func):
    def wrapper(bot, event):
        action = 'a' if os.path.exists('logs.txt') else 'w'
        with open('logs.txt', action) as file:
            f_name = str(func).split()[1]
            message = ''
            date = (datetime.now() + timedelta(hours=3)).strftime('%d.%m.%Y %H:%M')
            if f_name == 'buttons_answer_cb':
                message += f"{date}  {event.from_chat}  " \
                           f"{event.data['from']['lastName']} {event.data['from']['firstName']}  " \
                           f"{callback_dict[event.data['callbackData']]}\n"
            elif f_name == 'message_cb':
                message += f"{date}  {event.from_chat}  {event.data['from']['lastName']} " \
                           f"{event.data['from']['firstName']}  {event.data['text']}\n"

            if message: file.write(message)
            # print(message)
            func(bot, event)
    return wrapper