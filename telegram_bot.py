import os
import io
import datetime as dt
import xml.etree.ElementTree as ET
import contextlib
import telebot
from keybox_checker import analyze_key_node, print_human, human_timedelta

API_TOKEN = os.environ.get("KEYBOX_BOT_TOKEN")
if not API_TOKEN:
    raise RuntimeError("Environment variable KEYBOX_BOT_TOKEN is not set")

bot = telebot.TeleBot(API_TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Kirim file XML Keybox untuk diperiksa.")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.reply_to(message, f"Gagal mengunduh file: {e}")
        return

    try:
        root = ET.fromstring(downloaded_file)
    except Exception as e:
        bot.reply_to(message, f"Gagal mem-parsing XML: {e}")
        return

    now = dt.datetime.utcnow()
    key_nodes = root.findall('.//Keybox/Key')
    if not key_nodes:
        key_nodes = root.findall('.//Key')

    reports = [analyze_key_node(kn, now) for kn in key_nodes]

    out_stream = io.StringIO()
    with contextlib.redirect_stdout(out_stream):
        print("🔎 HASIL PEMERIKSAAN KEYBOX")
        print("---------------------------")
        for i, r in enumerate(reports, start=1):
            print_human(r, i, now)
            print()
        strong = any(
            r.alg == 'ecdsa' and r.private_key_ok and r.chain_ok and r.time_ok and r.root_trusted_google
            for r in reports
        )
        if strong:
            valid_untils = [
                r.not_after for r in reports
                if r.alg == 'ecdsa' and r.private_key_ok and r.chain_ok and r.time_ok and r.root_trusted_google
            ]
            if valid_untils:
                shortest = min(valid_untils)
                print(
                    f"💚 Status: VALID untuk STRONG integrity. Berlaku s/d {shortest.date()} (≈ {human_timedelta(now, shortest)})."
                )
        else:
            print("⚠️ Status: Tidak memenuhi kriteria 'STRONG' (cek catatan di atas).")

    bot.reply_to(message, out_stream.getvalue())

if __name__ == '__main__':
    bot.infinity_polling()
            
