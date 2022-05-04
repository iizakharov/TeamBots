import io
import json
import random
import re
import os
from datetime import datetime
import time

import requests
from bot.bot import Bot
from bot.handler import HelpCommandHandler, UnknownCommandHandler, MessageHandler, FeedbackCommandHandler, \
    CommandHandler, NewChatMembersHandler, LeftChatMembersHandler, PinnedMessageHandler, UnPinnedMessageHandler, \
    EditedMessageHandler, DeletedMessageHandler, StartCommandHandler, BotButtonCommandHandler
import logging.config

# logging.config.fileConfig('log.ini')
from thehive4py.api import TheHiveApi
from thehive4py.models import CaseTaskLog
from thehive4py.query import Eq

from env import BOT_TOKEN, BOT_SERVER_URL, THEHIVE_URL, THEHIVE_API_TOKEN, THEHIVE_EXTENSIONS
from utils import get_data_from_ipam, get_tenant_attacks, get_stat, get_gu_ad_stat, check_in_sed, make_files,\
    get_vpo_events
from env import VOCABLIARY as vb

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%Y.%m.%d %I:%M:%S %p', level=logging.DEBUG)


bot = Bot(token=BOT_TOKEN, api_url_base=BOT_SERVER_URL)


names = {
    'Мария': ["Машенька", "Машуля", "Маша", "Маш"],
    'Владимир': ['Володь', 'Вов', 'Вован', "НеПутин"],
}

mat = ['']
chats_to_send_notifications = [
    "",  # nick of a person
    "",  # nick of a person
]
# text_to_send = "Пора домой! Всем хорошего вечера \U0001F60A"
text_to_send = "Обед!!! Всем приятного аппетита  \U0001F60A"
allowed_chats = [
    '',
]

admins = [
    '',
]


def try_send(func):
    def wrapper(bot, event):
        if event.from_chat not in allowed_chats:
            print("NOT VALID")
            f_name = str(func).split()[1]

            if f_name == 'message_cb':
                if event.text.find('/') != 0:
                    message = "Внимание!" \
                        "\nБот подключён к чату: " + event.from_chat +\
                        "\nОтправитель: " + event.data['from']['userId'] +\
                        "\nПолученное сообщение: " + event.text
                else:
                    message = ""
            else:
                message = "Внимание!!!" \
                          "\nПопытка выполнения команды: " + f_name + \
                          "\nЧат: " + event.from_chat + \
                          "\nОтправитель: " + event.data['from']['userId']

            if message != "":
                for chat in admins:
                    bot.send_text(chat_id=chat, text=message)
            return None
        else:
            func(bot, event)
    return wrapper


@try_send
def send_alert(bot, event):
    for chat in chats_to_send_notifications:
        bot.send_text(chat_id=chat, text=text_to_send)


@try_send
def start_cb(bot, event):
    bot.send_text(chat_id=event.from_chat, text="Добро пожаловать!\n"
                                                "Я могу найти информацию по IP адресу. "
                                                "Для этого введите команду /ip и далее, искомый IP\n"
                                                "Формат ввода: '/ip 0.0.0.0'")


@try_send
def duty_cb(bot, event):
    dutys = {
        "Иванов": "заступил Иванов И.И.",
    }
    today = datetime.now().date()
    surname = event.data['from']['lastName']
    if surname in dutys.keys():
        message = f"{today.strftime('%d.%m')} на дежурство {dutys[surname]}"
    else:
        name = event.data['from']['lastName'] + str(event.data['from']['firstName'])[0] + '.'
        message = f"{today.strftime('%d.%m')} на дежурство заступил {name}"
    bot.send_text(chat_id=event.from_chat, text=message)


@try_send
def help_cb(bot, event):
    if event.chat_type == 'channel':
        bot.send_text(chat_id=event['chat']['chatId'],
                      text="Для меня доступны следующие команды:\n"
                           "/ip - Поиск информацию по IP адресу:\n"
                           "Формат ввода: '/ip 10.10.10.10'\n"
                           "/sed - Проверка IP адреса на входы в СЭД:\n"
                           "Формат ввода: '/sed 10.10.10.10'\n"
                           "/stat - Запрос статистику вручную\n"
                           "/statat - Получить данные по последим 50ти атакам в CSV и XLS\n"
                           "/guat - Получить данные по последним атакам за сутки в указанном ГУ:\n"
                           "Формат ввода: '/guat 32-GU'\n" 
                           "/guad - Получить последние 50 событий неудачной попытки входа в указанном ГУ:\n"
                           "Формат ввода: '/guad 32-GU'\n"
                           "/vpo - Получить события ВПО в указанном ГУ:\n"
                           "Формат ввода: '/vpo 32-GU'\n"
                 )
    else:
        bot.send_text(chat_id=event.from_chat,
                      text="Для меня доступны следующие команды:\n"
                           "/ip - Поиск информацию по IP адресу:\n"
                           "Формат ввода: '/ip 10.10.10.10'\n"
                           "/sed - Проверка IP адреса на входы в СЭД:\n"
                           "Формат ввода: '/sed 10.10.10.10'\n"
                           "/stat - Запрос статистику вручную\n"
                           "/statat - Получить данные по последим 50ти атакам в CSV и XLS\n"
                           "/guat - Получить данные по последним атакам за сутки в указанном ГУ:\n"
                           "Формат ввода: '/guat 32-GU'\n" 
                           "/guad - Получить последние 50 событий неудачной попытки входа в указанном ГУ:\n"
                           "Формат ввода: '/guad 32-GU'\n"
                           "/vpo - Получить события ВПО в указанном ГУ:\n"
                           "Формат ввода: '/vpo 32-GU'\n"
                      )


@try_send
def unknown_cb(bot, event):
    bot.send_text(chat_id=event.from_chat, text='Я не знаю такую команду')


@try_send
def ip_cb(bot,event):
    reg = re.compile(r'([0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3})')
    if event.text[:3] == '/ip':
        message = event.text[4:].strip()
    else:
        message = event.text.strip()
    # text = "Cool"
    if re.match(reg, message):
        ip = re.match(reg, message)
        ip = ip.group()
        res = get_data_from_ipam(ip)
        text = ''
        for k, v in res.items():
            if v:
                text += f'{vb[k]}: {v}\n'
    else:
        ip = None
        text = f'Не верный ввод IP адреса. Запрос должен быть формата:\n/ip 0.0.0.0'
    bot.send_text(chat_id=event.from_chat, text=text)


@try_send
def check_in_sed_cb(bot, event):
    reg = re.compile(r'([0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3})')
    if event.text[:4] == '/sed':
        message = event.text[5:].strip()
    else:
        message = event.text.strip()
    if re.match(reg, message):
        ip = re.match(reg, message)
        ip = ip.group()
        res = check_in_sed(ip)
        if res:
            data = {
                'fieldnames': ['Дата', 'Пользователь', 'Организация', 'Агент'],
                'source': res
            }
            f_name_csv, f_name_xls = make_files(data, 'sed_connects')
            bot.send_text(chat_id=event.from_chat, text='Пользователь заходил в СЭД!')
            with open(f_name_csv, 'r') as file:
                bot.send_file(chat_id=event.from_chat, file=file, caption='CSV Сводка по сетевым атакам')
            with open(f_name_xls, 'r+b') as file:
                bot.send_file(chat_id=event.from_chat, file=file, caption='XLS Сводка по сетевым атакам')
            os.remove(f_name_csv)
            os.remove(f_name_xls)

        else:
            text = f'За последние 30 дней входов в СЭД не зафиксированно!'
            bot.send_text(chat_id=event.from_chat, text=text)
    else:
        ip = None
        text = f'Не верный ввод IP адреса. Запрос должен быть формата:\n/sed 10.0.1.1'
        bot.send_text(chat_id=event.from_chat, text=text)
    return


# ЛОГИКА ДЛЯ ОБРАБОТКИ ФАЙЛОВ И ДАЛЬНЕЙШЕЙ ЗАГРУЗКИ В TheHive
answer_menu = [
    [{"text": "Да", "callbackData": "call_back_save"}],
    [{"text": "Нет", "callbackData": "call_back_exit"}]
]


def create_thehive_task_log(bot, event):
    user_dir = str(event.from_chat).replace('.', '_')
    api = TheHiveApi(THEHIVE_URL, THEHIVE_API_TOKEN)
    case_number = int(str(event.text).split(' ')[1])
    files = []
    if not os.path.exists('./' + user_dir):
        bot.send_text(chat_id=event.from_chat,
                      text='Нет доступных файлов.')
    for _file in os.listdir(user_dir):
        if _file.lower().endswith(THEHIVE_EXTENSIONS):
            files.append(user_dir + '/' + _file)
    if files:
        case = api.find_cases(query=Eq("caseId", case_number), range='all').json()
        task = api.get_case_tasks(case_id=case[0]['id'], query=Eq('title', 'Отчётные материалы')).json()
        if not task:
            bot.send_text(chat_id=event.from_chat,
                          text='Нет доступного таска (возможна ошибка названия).')
            return
        for file in files:
            print(file)
            log = api.create_task_log(task_id=task[0]['id'],
                                      case_task_log=CaseTaskLog(message='Из чата с ГУ', file=file))
            bot.send_text(chat_id=event.from_chat,
                          text=f'Фаил отправлен в кейс #{case_number} TheHive')
            os.remove(file)
        os.rmdir(user_dir)
    else:
        bot.send_text(chat_id=event.from_chat,
                      text='Нет доступных файлов.')


def post_to_thehive(bot, event, ext):
    bot.send_text(chat_id=event.from_chat,
                  text=f"Есть файл .{ext}, добавить его к материалам кейса в TheHive?",
                  inline_keyboard_markup="{}".format(json.dumps(answer_menu))
                  )


def message_file_manager(bot, event):
    # Проверка event на наличие файла, если найден файл, то будет предложено отправить в TheHive
    file_id = None
    try:
        file_id = event.data['parts'][0]['payload']['message']['parts'][0]['payload']['fileId']
    except:
        pass
    try:
        file_id = event.data['parts'][0]['payload']['fileId']
    except:
        pass
    if file_id:
        now = datetime.now().strftime("%Y%m%d%H%M%S")
        attempts = 10
        # Ссылки на файл в методе "get_file_info" генерируются очень часто "битые", и при каждом запросе разные,
        # для этого необходим цикл while
        while attempts > 0:
            file = bot.get_file_info(file_id).json()
            ext = str(file['filename']).split('.')[-1]

            img_data = requests.get(file['url']).content
            if img_data == b'{"status":404}':
                attempts -= 1
                continue
            else:
                user_dir = str(event.from_chat).replace('.', '_')
                if not os.path.exists(user_dir):
                    os.mkdir(user_dir)
                with open(f"{user_dir}/{now}.{ext}", "wb") as handle:
                    handle.write(img_data)
                post_to_thehive(bot, event, ext)
                break
        if attempts == 0:
            # print(json.dumps(event.data, ensure_ascii=False, indent=4))
            bot.send_text(chat_id=event.from_chat,
                          text=f"ОШИБКА! Попробуйте позже :("
                          )


@try_send
def call_back_save(bot, event):
    """
    Колбэк для кнопочного меню обработки файлов
    """
    user_dir = str(event.message_author).replace('.', '_')
    if event.data['callbackData'] == "call_back_exit":
        print('Удаление файла')
        files = []
        for file in os.listdir('./' + user_dir):
            if file.lower().endswith(THEHIVE_EXTENSIONS):
                files.append(file)
        if files:
            last_file = 0
            ext = ''
            for file in files:
                last_file = int(file.split('.')[0]) if last_file < int(file.split('.')[0]) else last_file
                ext = '.' + file.split('.')[1]
            os.remove(user_dir + "/" + str(last_file) + ext)
        else:
            os.rmdir(user_dir)
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text='Ок',
            show_alert=False
        )
        bot.delete_messages(chat_id=event.from_chat, msg_id=event.data['message']['msgId'])
    else:
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text='Пришлите команду /hive и номер кейса *TheHive*, пример:\n``` /hive 256 ```',
                      parse_mode="MarkdownV2"
                      )

# ЛОГИКА ДЛЯ ОБРАБОТКИ ФАЙЛОВ И ДАЛЬНЕЙШЕЙ ЗАГРУЗКИ В TheHive     <<<<<<<<<< END


@try_send
def message_cb(bot, event):
    flag = True
    some_nick = ''  # GROUP TEST  nick, stamp or chat_id
    home = ''
    if event.message_author['userId'] == home and event.data['chat']["chatId"]:
        pass
    if event.message_author['firstName'] in names.keys():
        name = names[event.message_author['firstName']][random.randint(0, 3)]
    else:
        name = event.message_author['firstName']
    print(name, datetime.now())
    message = '{0}, команду "{1}" я не научился понимать {2}!'.format(name, event.text, '\U0001F613')
    for word in mat:
        if word in str(event.text).upper():
            flag = False
            bot.send_text(chat_id=event.from_chat, text=f'Правила общения с ботом № {random.randint(1,999)}: '
                                                        f'- Никакого мата в чате!!! \U0001F621 \n'
                                                        f'{name}, немного спокойнее \U0001F609')
    if event.text == 'ping':
        bot.send_text(chat_id=some_nick, text="Alarm from BOT!")
    elif not(event.from_chat == some_nick):
        # Только в личных диалогах обрабатываются файлы<<<<<<<<<< END
        message_file_manager(bot, event)
    elif event.text == 'hello':
        bot.send_text(chat_id=some_nick, text="Всех приветствую!")
    elif event.text[:4] == '/say':
        message = event.text[4:].lstrip()
        bot.send_text(chat_id=some_nick, text=message)
    elif event.text == '/q':
        with open('main.py', 'r') as file:
            response = bot.send_file(chat_id=event.from_chat, file=file, caption="binary file caption")
            file_id = response.json()['fileId']
            print(response)
        #resp = bot.send_file(chat_id=event.from_chat, file='main.py')
    else:
        # if flag:
        #     bot.send_text(chat_id=event.from_chat, text=message)
        return
        #bot.send_text(chat_id=some_nick, text='Я не знаю такой команды \U0001F609')


@try_send
def stat_cb(bot, event):
    msg_id = bot.send_text(chat_id=event.from_chat,
                           text='Минуту, собираю информацию...',
                           parse_mode="MarkdownV2").json()['msgId']
    text = get_stat()
    if text is None:
        bot.edit_text(chat_id=event.from_chat, msg_id=msg_id,
                      text='Устал\U0001F613\n Давай в другой раз или сообщи разработчику,'
                           ' он сможет меня замотивировать \U0001F60D',
                      parse_mode="MarkdownV2")
    msg = bot.edit_text(chat_id=event.from_chat, msg_id=msg_id,
                  text=text,
                  parse_mode="MarkdownV2")

    if not msg.json()['ok']:
        text = text.replace("*__", "").replace("__*", "").replace("*", "")
        bot.edit_text(chat_id=event.from_chat, msg_id=msg_id, text=text)


@try_send
def statat_cb(bot, event):
    file_csv, file_xls = get_tenant_attacks(top50=True)
    with open(file_csv, 'r') as file:
        response = bot.send_file(chat_id=event.from_chat, file=file, caption='CSV Сводка по сетевым атакам')
    with open(file_xls, 'r+b') as file:
        response = bot.send_file(chat_id=event.from_chat, file=file, caption='XLS Сводка по сетевым атакам')
    os.remove(file_csv)
    os.remove(file_xls)


@try_send
def guat_cb(bot, event):
    tenant = event.text[6:].strip()
    if tenant == '':
        bot.send_text(chat_id=event.from_chat, text='Укажите название ГУ из в соответствии с высланной статистикой.')
    else:
        f_name_csv, f_name_xls = get_tenant_attacks(tenant)
        print(f_name_csv, f_name_xls)
        if f_name_csv and f_name_xls:
            with open(f_name_csv, 'r') as file:
                caption = 'CSV Сводка по сетевым атакам по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
            with open(f_name_xls, 'r+b') as file:
                caption = 'XLS Сводка по сетевым атакам по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
            os.remove(f_name_csv)
            os.remove(f_name_xls)
        else:
            bot.send_text(chat_id=event.from_chat, text='По указанному ГУ нет данных по атакам.')


@try_send
def guad_cb(bot, event):
    tenant = event.text[6:].strip()
    if tenant == '':
        bot.send_text(chat_id=event.from_chat, text='Укажите название ГУ из в соответствии с высланной статистикой.')
    else:
        f_name_csv, f_name_xls = get_gu_ad_stat(tenant)
        print(f_name_csv, f_name_xls)
        if f_name_csv and f_name_xls:
            with open(f_name_csv, 'r') as file:
                caption = 'CSV Сводка по неуспешным входам по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
                # print(response)
            with open(f_name_xls, 'r+b') as file:
                caption = 'XLS Сводка по неуспешным входам по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
                # print(response)
            os.remove(f_name_csv)
            os.remove(f_name_xls)
        else:
            bot.send_text(chat_id=event.from_chat, text='По указанному ГУ нет данных по атакам.')


@try_send
def vpo_cb(bot, event):
    days = None
    tenant = event.text[4:].strip()
    if ' ' in tenant:
        days = tenant.split(' ')[1]
        tenant = tenant.split(' ')[0]
    if tenant == '':
        bot.send_text(chat_id=event.from_chat,
                      text='Укажите название ГУ после команды, формат:\n``` /vpo 24-GU ```',
                      parse_mode="MarkdownV2")

    else:
        f_name_csv, f_name_xls = get_vpo_events(tenant, days)
        if f_name_csv == f_name_xls == "Clear":
            return bot.send_text(chat_id=event.from_chat, text='По указанному ГУ ВП0 были, но уже удалены антивирусом.')

        print(f_name_csv, f_name_xls)
        if f_name_csv and f_name_xls:
            with open(f_name_csv, 'r') as file:
                caption = 'CSV Сводка ВПО по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
                # print(response)
            with open(f_name_xls, 'r+b') as file:
                caption = 'XLS Сводка ВПО по учреждению: ' + tenant
                response = bot.send_file(chat_id=event.from_chat, file=file, caption=caption)
                # print(response)
            os.remove(f_name_csv)
            os.remove(f_name_xls)
        else:
            bot.send_text(chat_id=event.from_chat, text='По указанному ГУ нет ВП0 за период.')


@try_send
def buttons_answer_cb(bot, event):
    if event.data['callbackData'] == 'call_back_stat':
        stat_cb(bot, event)
    elif event.data['callbackData'] == 'call_back_statat':
        statat_cb(bot, event)


@try_send
def menu_cb(bot, event):
    bot.send_text(chat_id=event.from_chat,
                  text="Вы можете получить следующую информацию:",
                  inline_keyboard_markup="{}".format(json.dumps([[
                      # {"text": "Информация по IP", "callbackData": "call_back_ip", "style": "primary"},
                      {"text": "Запросить статистику вручную", "callbackData": "call_back_stat", "style": "primary"},
                      {"text": "Получить статистику в CSV", "callbackData": "call_back_statat", "style": "primary"},
                      # {"text": "Получить статистику по ГУ в CSV", "callbackData": "call_back_guat", "style": "primary"}
                  ]])))


@try_send
def send_secret_msg(bot, event):
    bot.send_text(chat_id="2354@chat.agent", text="Message sended!")


bot.dispatcher.add_handler(MessageHandler(callback=message_cb))
bot.dispatcher.add_handler(BotButtonCommandHandler(callback=buttons_answer_cb))
bot.dispatcher.add_handler(StartCommandHandler(callback=start_cb))
bot.dispatcher.add_handler(HelpCommandHandler(callback=help_cb))
bot.dispatcher.add_handler(CommandHandler(command='menu', callback=menu_cb))
bot.dispatcher.add_handler(UnknownCommandHandler(callback=unknown_cb))

bot.dispatcher.add_handler(CommandHandler(command="ip", callback=ip_cb))
bot.dispatcher.add_handler(CommandHandler(command="sed", callback=check_in_sed_cb))
bot.dispatcher.add_handler(CommandHandler(command="stat", callback=stat_cb))
bot.dispatcher.add_handler(CommandHandler(command="statat", callback=statat_cb))
bot.dispatcher.add_handler(CommandHandler(command="guat", callback=guat_cb))
bot.dispatcher.add_handler(CommandHandler(command="guad", callback=guad_cb))
bot.dispatcher.add_handler(CommandHandler(command="vpo", callback=vpo_cb))
bot.dispatcher.add_handler(CommandHandler(command="duty", callback=duty_cb))
bot.dispatcher.add_handler(CommandHandler(command="alarma", callback=send_alert))
bot.dispatcher.add_handler(CommandHandler(command="send_secret_msg", callback=send_secret_msg))
bot.dispatcher.add_handler(CommandHandler(command="hive", callback=create_thehive_task_log))
bot.dispatcher.add_handler(BotButtonCommandHandler(callback=call_back_save))
bot.start_polling()





