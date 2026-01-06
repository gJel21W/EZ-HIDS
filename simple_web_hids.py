import hashlib
import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime
import re
import requests
import yaml
import sys
import signal

CONFIG_PATH = "/etc/hids/config.yaml"

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Отсутствует файл конфигурации по пути {CONFIG_PATH}")
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
    required_keys = ['telegram', 'scan_interval', 'files_to_watch', 'log_files_to_monitor', 'baseline_file']
    missing = [k for k in required_keys if k not in config]
    if missing:
        raise ValueError(f"Отстутствуют значения  в конфигурации: {', '.join(missing)}")
    for log_entry in config.get('log_files_to_monitor', []):
        if 'alert_rules' in log_entry:
            for rule in log_entry['alert_rules']:
                try:
                    rule['compiled_regex'] = re.compile(rule['regex'], re.I)
                except re.error as e:
                    raise ValueError(f"неверный regex в {log_entry['path']}: {rule['regex']} - {e}")
    if config['telegram'].get('enabled', False):
        if config['telegram']['bot_token'] == "YOUR_BOT_TOKEN_HERE" or config['telegram']['chat_id'] == "YOUR_CHAT_ID_HERE":
            logging.warning("Отсутствует конфигурация телеграм. Уведомления отключены.")
            config['telegram']['enabled'] = False
    return config

class FIMonitor:
    def __init__(self, config):
        self.config = config
        self.baseline_path = config['baseline_file']

    @staticmethod
    def calculate_hash(filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (IOError, PermissionError) as e:
            logging.warning(f"Невозможно прочитать файл {filepath}: {e}")
            return None

    def create_baseline(self):
        baseline = {}
        for path in self.config['files_to_watch']:
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
        with open(self.baseline_path, 'w') as f:
            json.dump(baseline, f, indent=4)
        logging.info(f"Базовая линия создана. Записано {len(baseline)} файлов.")
        return baseline

    def load_baseline(self):
        if os.path.exists(self.baseline_path):
            with open(self.baseline_path, 'r') as f:
                return json.load(f)
        logging.warning("Базовая линия отсутствует. Запустите скрипт с параметром --create-baseline.")
        return {}

    def check_for_changes(self):
        alerts = []
        baseline = self.load_baseline()
        if not baseline:
            return alerts
        current_files = set()
        for path in self.config['files_to_watch']:
            p = Path(path)
            if p.is_file():
                file_str = str(p)
                current_files.add(file_str)
                current_hash = self.calculate_hash(file_str)
                if current_hash:
                    old_hash = baseline.get(file_str)
                    if not old_hash:
                        alerts.append(f"[FIM -> НОВЫЙ ФАЙЛ] Добавлен: {file_str}")
                    elif current_hash != old_hash:
                        alerts.append(f"[FIM -> ИЗМЕНЕНИЕ] Файл изменен: {file_str} (старый файл: {old_hash[:10]}..., новый файл: {current_hash[:10]}...)")
            elif p.is_dir():
                for file in p.rglob("*"):
                    if file.is_file():
                        file_str = str(file)
                        current_files.add(file_str)
                        current_hash = self.calculate_hash(file_str)
                        if current_hash:
                            old_hash = baseline.get(file_str)
                            if not old_hash:
                                alerts.append(f"[FIM -> НОВЫЙ ФАЙЛ] Добавлен: {file_str}")
                            elif current_hash != old_hash:
                                alerts.append(f"[FIM -> ИЗМЕНЕНИЕ] Файл  изменен: {file_str} (старый файл: {old_hash[:10]}..., новый файл: {current_hash[:10]}...)")
        for tracked_file in list(baseline.keys()):
            if tracked_file not in current_files:
                alerts.append(f"[FIM -> УДАЛЕНИЕ] Файл удален: {tracked_file}")
        return alerts

class LogAnalyzer:
    def __init__(self):
        self.file_pointers = {}

    def analyze_new_entries(self, log_path, alert_rules):
        alerts = []
        if not os.path.exists(log_path):
            logging.warning(f"Лог файл не найден: {log_path}")
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
                    for rule in alert_rules:
                        if rule['compiled_regex'].search(line):
                            alert_msg = (
                                f"[ЛОГ -> {rule['name'].upper()}]\n"
                                f"Файл: {log_path}\n"
                                f"Строка: {line_num + current_position // 80} (approx)\n"
                                f"Паттерн: {rule['regex'][:50]}...\n"
                                f"Запись: {line[:200]}..."
                            )
                            alerts.append(alert_msg)
                            break
        except Exception as e:
            logging.error(f"Ошибка чтения лог-файла {log_path}: {e}")
        return alerts

class AlertSystem:
    def __init__(self, config):
        self.config = config

    def send_telegram_alert(self, message):
        if not self.config['telegram']['enabled']:
            return False
        bot_token = self.config['telegram']['bot_token']
        chat_id = self.config['telegram']['chat_id']
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        try:
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logging.error(f"Ошибка Telegram API: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Ошибка запроса к Telegram: {e}")
            return False

    @staticmethod
    def console_alert(message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

def main_loop(config):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("/var/log/ez_hids.log"),
            logging.StreamHandler()
        ]
    )
    logging.info("Запуск EZ-HIDS...")
    fim = FIMonitor(config)
    log_analyzer = LogAnalyzer()
    alerter = AlertSystem(config)

    def signal_handler(sig, frame):
        logging.info("Выключение EZ-HIDS.")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    while True:
        all_alerts = []
        timestamp = datetime.now().strftime("%H:%M:%S")
        fim_alerts = fim.check_for_changes()
        all_alerts.extend(fim_alerts)
        for log_entry in config['log_files_to_monitor']:
            log_path = log_entry['path']
            alert_rules = log_entry.get('alert_rules', [])
            log_alerts = log_analyzer.analyze_new_entries(log_path, alert_rules)
            all_alerts.extend(log_alerts)
        if all_alerts:
            consolidated_message = f"<b> EZ-HIDS тревога ({timestamp})</b>\n\n" + "\n---\n".join(all_alerts)
            alerter.console_alert(f"Количество обнаруженных инцидентов: {len(all_alerts)}")
            alerter.send_telegram_alert(consolidated_message[:4096])
        time.sleep(config['scan_interval'])

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="EZ-HIDS: Система обнаружения вторжений (HIDS) для веб-серверов")
    parser.add_argument("--create-baseline", action="store_true", help="Создание базовой линии хэшей файлов")
    args = parser.parse_args()
    try:
        config = load_config()
    except Exception as e:
        print(f"Config error: {e}")
        sys.exit(1)
    fim = FIMonitor(config)
    if args.create_baseline:
        print("Создание базовой линии файлов...")
        fim.create_baseline()
        print(f"Базовая линия сохранена в {config['baseline_file']}")
    else:
        main_loop(config)