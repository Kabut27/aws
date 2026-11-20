import os
DATA_DIR = os.environ.setdefault("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
os.environ.setdefault("DB_FILE", os.path.join(DATA_DIR, "bot_data.db"))
os.environ.setdefault("BACKUP_DIR", os.path.join(DATA_DIR, "backups"))
os.environ.setdefault("ADMIN_IDS", "")

import logging
from telegram import BotCommand
from telegram.ext import CommandHandler, CallbackQueryHandler, MessageHandler, filters
import bot, freetier


async def post_init(app):
    await bot.post_init(app)
    cmds = await app.bot.get_my_commands()
    await app.bot.set_my_commands(list(cmds) + [BotCommand("freetier", "Hali ya free tier (CF + EC2)")])


def main():
    bot.init_db()
    app = bot.Application.builder().token(bot.TOKEN).post_init(post_init).build()
    freetier.setup(app)
    app.add_handler(CommandHandler(["start", "menu", "cancel"], bot.cmd_start))
    app.add_handler(CallbackQueryHandler(bot.on_cb))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.on_text))
    if app.job_queue:
        app.job_queue.run_repeating(bot.job_watchers, interval=30, first=15)
        app.job_queue.run_repeating(bot.job_health_alerts, interval=1800, first=120)
    else:
        logging.warning("JobQueue haipo! requirements lazima iwe python-telegram-bot[job-queue]")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
