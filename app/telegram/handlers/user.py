from datetime import datetime
from app.db import GetDB, crud
from app.models.user import UserResponse
from app.telegram import bot
from telebot.custom_filters import ChatFilter
from telebot.util import extract_arguments

from app.utils.system import readable_size

bot.add_custom_filter(ChatFilter())


@bot.message_handler(commands=['usage'])
def usage_command(message):
    username = extract_arguments(message.text)
    if not username:
        return bot.reply_to(message, 'Usage: `/usage <username>`', parse_mode='MarkdownV2')

    with GetDB() as db:
        dbuser = crud.get_user(db, username)

        if not dbuser:
            return bot.reply_to(message, "No user found with this username")
        user = UserResponse.model_validate(dbuser)
        sessions = [dict(ip=r.ip, device=r.device, device_name=r.device_name or '')
                    for r in crud.get_user_online_ips(db, dbuser)]

        statuses = {
            'active': '✅',
            'expired': '🕰',
            'limited': '📵',
            'disabled': '❌'}

        device_limit = user.ip_limit if user.ip_limit else 'Unlimited'
        online_device_count = len({s['device'] for s in sessions})

        text = f'''\
┌─{statuses[user.status]} <b>Status:</b> <code>{user.status.title()}</code>
│          └─<b>Username:</b> <code>{user.username}</code>
│
├─🔋 <b>Data limit:</b> <code>{readable_size(user.data_limit) if user.data_limit else 'Unlimited'}</code>
│          └─<b>Data Used:</b> <code>{readable_size(user.used_traffic) if user.used_traffic else "-"}</code>
│
├─📱 <b>Device limit:</b> <code>{device_limit}</code>
│          └─<b>Online devices:</b> <code>{online_device_count}</code>
│
└─📅 <b>Expiry Date:</b> <code>{datetime.fromtimestamp(user.expire).date() if user.expire else 'Never'}</code>
            └─<b>Days left:</b> <code>{(datetime.fromtimestamp(user.expire or 0) - datetime.now()).days if user.expire else '-'}</code>'''

    return bot.reply_to(message, text, parse_mode='HTML')