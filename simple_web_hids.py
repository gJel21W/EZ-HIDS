import hashlib
import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime
import re
import requests

# Конфигурация программы
CONFIG = {
    # Пути для мониторинга
    "paths_to_watch": [
        "/var/www/html", # Корень веб-сайта
        "/etc/nginx/nginx.conf", # Основной конфиг Nginx
        "/etc/nginx/sites-available/", # Конфиги сайтов
    ],
    # Лог-файлы для анализа
    "log_files": {
        "/var/log/nginx/access.log": ["nginx_access"],
        "/var/log/nginx/error.log": ["nginx_error"],
        "/var/log/apache2/access.log": ["apache_access"],
        "/var/log/apache2/error.log": ["apache_error"],
    },
    # Регулярные выражения для поиска угроз в логах
    "log_patterns": {
        "sql_injection": re.compile(r'(\%27)|(\')|(\-\-)|(\%23)|(#)|(union.*select)', re.I),
        "path_traversal": re.compile(r'(\.\./)|(\.\.\\\\)', re.I),
        "xss_attempt": re.compile(r'((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)', re.I),
        "scanner_bot": re.compile(r'(nikto|sqlmap|wget|curl|nessus|acunetix)', re.I),
        "auth_failure": re.compile(r'(failed|invalid|authentication error)', re.I),
    },
    # Настройки Telegram Bot API
    "telegram": {
        "bot_token": "ВАШ_TELEGRAM_BOT_TOKEN",# Необходимо получить в @BotFather
        "chat_id": "ВАШ_CHAT_ID", # Можно узнать в @userinfobot
        "enabled": True # Включение/отключение оповещений
    },
    # Файл для хранения эталонных хэшей (базовая линия)
    "baseline_file": "/var/tmp/hids_baseline.json",
    # Интервал проверки в секундах
    "check_interval": 60
}

# Модуль FIM (мониторинг целостности файлов)
class FIMonitor:
    """Мониторинг целостности файлов через хэши SHA-256."""

    @staticmethod
    def calculate_hash(filepath):
        """Вычисляет SHA-256 хэш файла."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, PermissionError) as e:
            logging.warning(f"Не могу прочитать файл {filepath}: {e}")
            return None

    def create_baseline(self):
        """Создает первоначальную базу хэшей (базовую линию)."""
        baseline = {}
        for path in CONFIG["paths_to_watch"]:
            p = Path(path)
            if p.is_file():
                file_hash = self.calculate_hash(str(p))
                if file_hash:
                    baseline[str(p)] = file_hash
            elif p.is_dir():
                for file in p.rglob("*"):
                    if file.is_file():
                        file_hash = self.calculate_hash(str(file))
                        if file_hash:
                            baseline[str(file)] = file_hash
        # Сохраняем в файл
        with open(CONFIG["baseline_file"], 'w') as f:
            json.dump(baseline, f, indent=4)
        logging.info(f"Базовая линия создана. Записано {len(baseline)} файлов.")
        return baseline

    def load_baseline(self):
        """Загружает базу хэшей из файла."""
        if os.path.exists(CONFIG["baseline_file"]):
            with open(CONFIG["baseline_file"], 'r') as f:
                return json.load(f)
        return {}

    def check_for_changes(self):
        """Сравнивает текущие хэши с базовой линией и сообщает об изменениях."""
        alerts = []
        baseline = self.load_baseline()
        if not baseline:
            logging.warning("Базовая линия отсутствует. Запустите скрипт с ключом '--create-baseline'.")
            return alerts

        current_files = set()
        # Вычисляем хэши для всех отслеживаемых файлов
        for path in CONFIG["paths_to_watch"]:
            p = Path(path)
            if p.is_file():
                current_files.add(str(p))
                current_hash = self.calculate_hash(str(p))
                if current_hash:
                    old_hash = baseline.get(str(p))
                    if not old_hash:
                        alerts.append(f"[FIM -> НОВЫЙ ФАЙЛ] Добавлен: {p}")
                    elif current_hash != old_hash:
                        alerts.append(f"[FIM -> ИЗМЕНЕНИЕ] Файл изменен: {p}")
            elif p.is_dir():
                for file in p.rglob("*"):
                    if file.is_file():
                        file_str = str(file)
                        current_files.add(file_str)
                        current_hash = self.calculate_hash(file_str)
                        if current_hash:
                            old_hash = baseline.get(file_str)
                            if not old_hash:
                                alerts.append(f"[FIM -> НОВЫЙ ФАЙЛ] Добавлен: {file}")
                            elif current_hash != old_hash:
                                alerts.append(f"[FIM -> ИЗМЕНЕНИЕ] Файл изменен: {file}")

        # Проверяем удаленные файлы
        for tracked_file in baseline.keys():
            if tracked_file not in current_files:
                alerts.append(f"[FIM -> УДАЛЕНИЕ] Файл удален: {tracked_file}")

        return alerts

# Модкль анализа лог-файлов
class LogAnalyzer:
    """Анализирует логи веб-сервера на предмет подозрительной активности."""

    def __init__(self):
        self.file_pointers = {}  # Храним позицию в файле для каждого лога

    def analyze_new_entries(self, log_path, log_types):
        """Читает новые строки в лог-файле и проверяет их по шаблонам."""
        alerts = []
        if not os.path.exists(log_path):
            return alerts

        current_position = self.file_pointers.get(log_path, 0)
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(current_position)
                new_lines = f.readlines()
                self.file_pointers[log_path] = f.tell()

                for line_num, line in enumerate(new_lines, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    for rule_name, pattern in CONFIG["log_patterns"].items():
                        if pattern.search(line):
                            alert_msg = (
                                f"[LOG -> {rule_name.upper()}]\n"
                                f"Файл: {log_path}\n"
                                f"Строка: {line_num}\n"
                                f"Образец: {pattern.pattern[:50]}...\n"
                                f"Запись: {line[:200]}..."
                            )
                            alerts.append(alert_msg)
                            break  # Не проверяем другие правила для этой строки
        except Exception as e:
            logging.error(f"Ошибка чтения лога {log_path}: {e}")

        return alerts

# Модуль оповещений в телеграмм
class AlertSystem:
    """Отправка оповещений через Telegram Bot API."""

    @staticmethod
    def send_telegram_alert(message):
        """Отправляет сообщение в Telegram чат."""
        if not CONFIG["telegram"]["enabled"]:
            return False

        bot_token = CONFIG["telegram"]["bot_token"]
        chat_id = CONFIG["telegram"]["chat_id"]
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        try:
            response = requests.post(url, data=payload, timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logging.error(f"Ошибка отправки в Telegram: {e}")
            return False

    @staticmethod
    def console_alert(message):
        """Выводит оповещение в консоль с временной меткой."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

# Основной цикл
def main_loop():
    """Основной цикл мониторинга."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("/var/tmp/hids.log"),
            logging.StreamHandler()
        ]
    )

    logging.info("Запуск HIDS для веб-сервера...")
    fim = FIMonitor()
    log_analyzer = LogAnalyzer()
    alerter = AlertSystem()

    # Проверка конфигурации Telegram
    if CONFIG["telegram"]["enabled"]:
        if "ВАШ_TELEGRAM_BOT_TOKEN" in CONFIG["telegram"]["bot_token"]:
            logging.warning("Telegram токен не настроен. Оповещения отключены.")
            CONFIG["telegram"]["enabled"] = False

    logging.info(f"Мониторинг запущен. Интервал проверки: {CONFIG['check_interval']}с")

    try:
        while True:
            all_alerts = []
            timestamp = datetime.now().strftime("%H:%M:%S")

            # Проверка целостности файлов
            fim_alerts = fim.check_for_changes()
            all_alerts.extend(fim_alerts)

            # Анализ логов
            for log_file in CONFIG["log_files"]:
                log_alerts = log_analyzer.analyze_new_entries(log_file, CONFIG["log_files"][log_file])
                all_alerts.extend(log_alerts)

            # Оповещение о всех обнаруженных инцидентах
            if all_alerts:
                consolidated_message = f"<b>🚨 HIDS Оповещение ({timestamp})</b>\n" + "\n---\n".join(all_alerts)
                alerter.console_alert(f"Обнаружено {len(all_alerts)} инцидента(ов).")
                if CONFIG["telegram"]["enabled"]:
                    alerter.send_telegram_alert(consolidated_message[:4000])  # Обрезка для лимита Telegram
            else:
                logging.debug(f"Проверка {timestamp} - угроз не обнаружено.")

            time.sleep(CONFIG["check_interval"])

    except KeyboardInterrupt:
        logging.info("Мониторинг остановлен пользователем.")
    except Exception as e:
        logging.critical(f"Критическая ошибка в основном цикле: {e}", exc_info=True)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HIDS для веб-серверов")
    parser.add_argument("--create-baseline", action="store_true", help="Создать первоначальную базу хэшей файлов")
    args = parser.parse_args()

    fim = FIMonitor()
    if args.create_baseline:
        print("Создание базовой линии файлов...")
        fim.create_baseline()
        print(f"Базовая линия сохранена в {CONFIG['baseline_file']}")
    else:
        main_loop()