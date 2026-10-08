import re
import sqlite3
from datetime import datetime
import requests

# ========== НАСТРОЙКИ ==========
TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"     # получи у @BotFather
CHAT_ID = "YOUR_CHAT_ID"               # узнай через @userinfobot
PROXY = "http://user:password@ip:port" # укажи свой прокси
THRESHOLD = 10   # Количество неудачных попыток для обнаружения атаки
# ===============================

proxies = {
    "http": PROXY,
    "https": PROXY
}

# Подключаем базу данных
conn = sqlite3.connect('alerts.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS alerts
             (ip TEXT, timestamp TEXT, attempts INTEGER)''')
conn.commit()

def send_telegram(message):
    """Отправляет сообщение в Telegram через прокси"""
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": message}
    try:
        response = requests.post(url, json=payload, proxies=proxies, timeout=30)
        if response.status_code == 200:
            print("✅ Уведомление отправлено в Telegram")
        else:
            print(f"❌ Ошибка при отправке: {response.status_code}")
            print(f"Ответ: {response.text}")
    except Exception as e:
        print(f"❌ Ошибка сети или прокси: {e}")

def parse_log(file_path):
    """Извлекает IP-адреса из строк лога"""
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    events = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    events.append(match.group(1))
        print(f"Прочитано {len(events)} событий из {file_path}")
    except FileNotFoundError:
        print(f"❌ Файл {file_path} не найден!")
    return events

def detect_bruteforce(events):
    """Анализирует события и выявляет IP с превышением порога"""
    counts = {}
    for ip in events:
        counts[ip] = counts.get(ip, 0) + 1
    alerts = [(ip, cnt) for ip, cnt in counts.items() if cnt >= THRESHOLD]
    return alerts

def main():
    log_file = "moodle_fake.log"
    print("=" * 50)
    print("Анализатор логов безопасности ОГУ")
    print("=" * 50)

    events = parse_log(log_file)
    if not events:
        print("Нет событий для анализа. Завершение.")
        return

    alerts = detect_bruteforce(events)

    if not alerts:
        print("Атак не обнаружено.")
    else:
        print(f"\n🚨 Обнаружено {len(alerts)} атак!")
        for ip, cnt in alerts:
            message = f"🚨 БРУТФОРС-АТАКА!\nIP: {ip}\nНеудачных попыток: {cnt}\nВремя: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            print(f"\n{message}")
            send_telegram(message)
            # Сохраняем в базу данных
            c.execute("INSERT INTO alerts VALUES (?, ?, ?)", (ip, datetime.now().isoformat(), cnt))
            conn.commit()
            print(f"✅ Алерт для IP {ip} сохранён в БД")

    print("\n" + "=" * 50)
    print("Работа завершена.")

if __name__ == "__main__":
    main()
    input("Нажмите Enter для выхода...")
