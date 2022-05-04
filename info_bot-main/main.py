import io
import json
import sys

from bot.bot import Bot
from bot.handler import MessageHandler, BotButtonCommandHandler, DeletedMessageHandler, EditedMessageHandler, \
    StartCommandHandler, CommandHandler
from bot.constant import ParseMode
from bot.types import Format
import logging.config

# logging.config.fileConfig("logging.ini")
from gtts import gTTS

from utils import try_send, home_menu, instruction_menu, button_home

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%Y.%m.%d %I:%M:%S %p', level=logging.DEBUG)

TOKEN = ""
# TOKEN = ""  # DEBUG
# docker cp 08a03d9782cc:/opt/bot/logs.txt ./
SERVER_URL = ''
EVENT_CHAT = ''
bot = Bot(token=TOKEN, api_url_base=SERVER_URL)

"""
*bold*
_italic_
__underline__
~strikethrought~
[url](https://example.com)
[mention]
`inline_code`
```
pre-formatted fixed-width code block
```
```python
pre-formatted fixed-width code block written in the Python programming language
```
Ordered list:
1. First element
2. Second element
Unordered list:
- First element
- Second element
Quote:
>Begin of quote
>End of quote
"""

messages = {
    "information": "*О сервисе*\n",
    "contacts": "*Контакты*\n",
    'terms': "*__Основные термины и определения.__*\n\n",
    'fishing': "*При фишинге:*\n",
    "vpo": "*При обнаружении ВПО:*\n",
    "network_attack": "*При сетевых атаках:*\n",
    "savz_status_critical": "*САВЗ в статусе критический*\n",
    "without_mi": "*Доступ к СЭД/ГИМС без МИ*\n",
}

_msg = ''


@try_send
def start_cb(bot, event):
    answer = 'Доброго времени суток!\nВыберите интересующий вас вопрос:'
    bot.send_text(chat_id=event.from_chat,
                  text=answer,
                  inline_keyboard_markup="{}".format(json.dumps(home_menu))  # "style": "primary"}
                  )


@try_send
def help_cb(bot, event):
    bot.send_text(chat_id=event.data['chat']['chatId'],
                  text="Для начала работы напишите команду /start\n"
                       "Если хотите сообщить от инциденте воспользутесь командой /say и опишите ситуацию, пример:\n"
                       "``` /say Обнаружено фишинговое письмо (описание ситуации)... "
                       "Контакты для обратной связи:...```",
                  parse_mode="MarkdownV2")


@try_send
def say_cb(bot, event):
    message = "СООБЩЕНИЕ ОБ ИНЦИДЕНТЕ!\n\n"
    message += event.data['text'][4:]
    message += f"\n\nОт пользователя: {event.from_chat} ({event.data['from']['lastName']} " \
               f"{event.data['from']['firstName']})"
    bot.send_text(chat_id=EVENT_CHAT, text=str(message).strip())
    bot.send_text(chat_id=event.from_chat,
                  text="Ваше сообщение отправлено!\n Введите команду /start для продолжения работы с ботом",
                  parse_mode="MarkdownV2",
                  # inline_keyboard_markup="{}".format(json.dumps(home_menu))
                  )


@try_send
def message_cb(bot, event):
    if event.data['text'][:6] == '/voice':
        # Send voice file
        data = str(event.data['text'][6:]).strip()
        if not data:
            return
        if sys.version_info[0] == 3:
            with io.BytesIO() as file:
                gTTS(data, lang='ru').write_to_fp(file)
                file.name = "hello_voice.mp3"
                file.seek(0)
                response = bot.send_voice(chat_id=event.from_chat, file=file.read())
                hello_voice_file_id = response.json()['fileId']
    elif event.data['text'][0] != '/':
        bot.send_text(chat_id=event.from_chat,
                      text='Если вы хотите сообщить об инциденте, перед текстом напишите команду "/say"',
                      parse_mode="MarkdownV2")
    else:
        print(event)


@try_send
def buttons_answer_cb(bot, event):
    global msg_list
    global _msg
    if event.data['callbackData'] == "call_back_contacts":
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text='Загружаю контакты',
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['contacts'],
                      parse_mode="MarkdownV2",
                      inline_keyboard_markup="{}".format(json.dumps(home_menu))
                      )

    elif event.data['callbackData'] == "call_back_url":
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Сообщить об инциденте...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text='Напишите информацию сюда, обязательным условием будет указание вначале сообщения '
                           'команды /say, формат:\n``` /say '
                           'Обнаружено фишинговое письмо (описание ситуации).... Контакты для обратной связи:...```\n'
                           'Либо отправьте письмом по адресу: @mail.ru',
                      inline_keyboard_markup="{}".format(json.dumps(button_home)),
                      parse_mode="MarkdownV2"
                      )

    elif event.data['callbackData'] == "call_back_instructions":
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Получаю инструкции...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text='Есть инструкции по темам:',
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu))
                      )
    elif event.data['callbackData'] == "call_back_fishing":
        
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Проверяю актуальную информацию о фишинге...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['fishing'],
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu)),
                      parse_mode="MarkdownV2"
                      )

    elif event.data['callbackData'] == "call_back_vpo":
        
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Проверяю актуальную информацию о ВПО...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['vpo'],
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu)),
                      parse_mode="MarkdownV2"
                      )

    elif event.data['callbackData'] == "call_back_network_attacks":
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Проверяю актуальную информацию о сетевых атаках...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['network_attack'],
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu)),
                      parse_mode="MarkdownV2"
                      )
    # САВЗ Критический
    elif event.data['callbackData'] == "call_back_savz_stat_critical":
        bot.answer_callback_query(
            query_id=event.data['queryId'],
            text="Проверяю актуальную информацию...",
            show_alert=False
        )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['savz_status_critical'],
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu)),
                      parse_mode="MarkdownV2"
                      )
    # МИ не установлен
    elif event.data['callbackData'] == "call_back_without_mi":
        bot.answer_callback_query(query_id=event.data['queryId'],
                                  text="Проверяю актуальную информацию...",
                                  show_alert=False
                                  )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['without_mi'],
                      inline_keyboard_markup="{}".format(json.dumps(instruction_menu)),
                      parse_mode="MarkdownV2"
                      )
    elif event.data['callbackData'] in ['call_back_home', 'call_back_back']:
        answer = 'Доброго времени суток!\nВыберите интересующий вас вопрос:'
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=answer,
                      inline_keyboard_markup="{}".format(json.dumps(home_menu))  # "style": "primary"}
                      )
    elif event.data['callbackData'] == 'call_back_information':
        bot.answer_callback_query(query_id=event.data['queryId'],
                                  text="Проверяю актуальную информацию...",
                                  show_alert=False
                                  )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['information'],
                      inline_keyboard_markup="{}".format(json.dumps(home_menu)),
                      parse_mode="MarkdownV2"
                      )
    elif event.data['callbackData'] == 'call_back_terms':
        bot.answer_callback_query(query_id=event.data['queryId'],
                                  text="Загружаю справочник...",
                                  show_alert=False
                                  )
        bot.edit_text(chat_id=event.from_chat, msg_id=event.data['message']['msgId'],
                      text=messages['terms'],
                      inline_keyboard_markup="{}".format(json.dumps(home_menu)),
                      parse_mode="MarkdownV2"
                      )


bot.dispatcher.add_handler(StartCommandHandler(callback=start_cb))
bot.dispatcher.add_handler(MessageHandler(callback=message_cb))
bot.dispatcher.add_handler(BotButtonCommandHandler(callback=buttons_answer_cb))
bot.dispatcher.add_handler(CommandHandler(command="say", callback=say_cb))

bot.start_polling()
bot.idle()
