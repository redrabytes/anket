from anket.core import *

async def TelegramMessage(chat_id, message, bot):
    max_message_length = 4096

    if len(message) > max_message_length:
        message_parts = [message[i:i + max_message_length] for i in range(0, len(message), max_message_length)]
    else:
        message_parts = [message]

    for part in message_parts:
        try:
            await bot.send_message(chat_id, part)
        except Exception as e:
            logging.error(f"Error sending Telegram message: {e}")
