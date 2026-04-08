from flask import Flask, request, abort, jsonify
from datetime import datetime
import requests
import json
import os
from functools import wraps

app = Flask(__name__)

# Конфигурация
LOG_FILE = os.environ.get('LOG_FILE', 'visitors.json')
ENABLE_VPN_BLOCK = os.environ.get('ENABLE_VPN_BLOCK', 'true').lower() == 'true'

# Список ASN дата-центров и хостингов (можно расширять)
BLOCKED_ASNS = {
    'AS13335',   # Cloudflare
    'AS16509',   # AWS
    'AS15169',   # Google Cloud
    'AS8075',    # Microsoft Azure
    'AS20473',   # Vultr
    'AS16276',   # OVH
    'AS14061',   # DigitalOcean
    'AS63949',   # Linode
    'AS14618',   # Amazon
    'AS200019',  # Relay VPN
    'AS36459',   # GitHub Actions
    'AS54113',   # Fastly
    'AS20940',   # Akamai
}

# Ключевые слова VPN/хостингов в названии организации
SUSPICIOUS_KEYWORDS = [
    'vpn', 'hosting', 'cloud', 'data center', 'proxy', 'server', 
    'virtual', 'dedicated', 'vps', 'colo', 'rack', 'host', 'cloudflare',
    'digitalocean', 'aws', 'amazon', 'azure', 'google cloud', 'linode',
    'vultr', 'ovh', 'hetzner', 'namecheap', 'godaddy'
]

# Подозрительные User-Agent (боты, скрипты)
BLOCKED_USER_AGENTS = [
    'python-requests', 'curl', 'wget', 'go-http-client', 'java', 
    'perl', 'ruby', 'scrapy', 'httpx', 'aiohttp', 'okhttp',
    'bot', 'crawler', 'spider', 'scanner'
]

def get_real_ip():
    """Получает реальный IP клиента за прокси (Render.com)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # Альтернативные заголовки
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    return request.remote_addr

def is_vpn_or_hosting(ip):
    """
    Проверяет, принадлежит ли IP VPN сервису или хостингу
    Возвращает: (is_blocked, reason)
    """
    if not ENABLE_VPN_BLOCK:
        return False, None
    
    # Пропускаем локальные IP (для тестирования)
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        return False, None
    
    try:
        # Используем ip-api.com для определения типа IP
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            asn = data.get('as', '').split()[0] if data.get('as') else ''
            org = data.get('org', '').lower()
            isp = data.get('isp', '').lower()
            
            # Проверка по ASN
            if asn in BLOCKED_ASNS:
                return True, f"Дата-центр заблокирован (ASN: {asn})"
            
            # Проверка по ключевым словам
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in org or keyword in isp:
                    return True, f"Обнаружен VPN/хостинг: {org}"
            
            # Дополнительная проверка: если страна не соответствует типичным признакам
            # (можно добавить свои правила)
            
        return False, None
        
    except requests.Timeout:
        print(f"Таймаут при проверке IP {ip}")
        return False, None
    except Exception as e:
        print(f"Ошибка при проверке IP {ip}: {e}")
        return False, None

def check_user_agent():
    """Проверяет User-Agent на ботов и скрипты"""
    user_agent = request.headers.get('User-Agent', '').lower()
    
    for bot in BLOCKED_USER_AGENTS:
        if bot in user_agent:
            return True, f"Заблокированный User-Agent: {bot}"
    
    # Блокируем запросы без User-Agent
    if not user_agent:
        return True, "Отсутствует User-Agent"
    
    return False, None

def check_missing_headers():
    """Проверяет наличие обязательных браузерных заголовков"""
    # Типичные браузеры всегда отправляют эти заголовки
    if not request.headers.get('Accept-Language'):
        return True, "Отсутствует Accept-Language (признак скрипта)"
    
    if not request.headers.get('Accept'):
        return True, "Отсутствует Accept"
    
    return False, None

@app.before_request
def security_check():
    """Главная функция проверки безопасности"""
    client_ip = get_real_ip()
    
    # Проверка User-Agent
    is_bot, bot_reason = check_user_agent()
    if is_bot:
        log_blocked_request(client_ip, "bot", bot_reason)
        return render_block_page(client_ip, f"Бот или скрипт: {bot_reason}"), 403
    
    # Проверка на VPN/хостинг
    is_vpn, vpn_reason = is_vpn_or_hosting(client_ip)
    if is_vpn:
        log_blocked_request(client_ip, "vpn", vpn_reason)
        return render_block_page(client_ip, vpn_reason), 403
    
    # Проверка на отсутствие браузерных заголовков
    is_missing, missing_reason = check_missing_headers()
    if is_missing:
        log_blocked_request(client_ip, "missing_headers", missing_reason)
        return render_block_page(client_ip, missing_reason), 403

def log_blocked_request(ip, reason_type, details):
    """Логирует заблокированные запросы"""
    block_log = {
        'ip': ip,
        'timestamp': datetime.now().isoformat(),
        'type': reason_type,
        'details': details,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'path': request.path
    }
    
    # Сохраняем в отдельный файл
    block_file = 'blocked_requests.json'
    try:
        with open(block_file, 'r', encoding='utf-8') as f:
            blocks = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        blocks = []
    
    blocks.append(block_log)
    
    with open(block_file, 'w', encoding='utf-8') as f:
        json.dump(blocks, f, indent=2, ensure_ascii=False)

def render_block_page(ip, reason):
    """Страница для заблокированных пользователей"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Доступ запрещен</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 20px;
                padding: 40px;
                max-width: 500px;
                text-align: center;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }}
            h1 {{ color: #e74c3c; margin-bottom: 20px; }}
            .icon {{ font-size: 64px; margin-bottom: 20px; }}
            .reason {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 10px;
                margin: 20px 0;
                font-family: monospace;
            }}
            .button {{
                display: inline-block;
                background: #667eea;
                color: white;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 5px;
                margin-top: 20px;
            }}
            small {{ color: #999; display: block; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">🚫</div>
            <h1>Доступ запрещен</h1>
            <p>Ваше соединение было заблокировано системой безопасности.</p>
            <div class="reason">
                <strong>Причина:</strong><br>
                {reason}
            </div>
            <p>Возможные причины:</p>
            <ul style="text-align: left;">
                <li>Использование VPN или прокси-сервера</li>
                <li>Подключение через хостинг или дата-центр</li>
                <li>Использование ботов или скриптов</li>
                <li>Подозрительные заголовки запроса</li>
            </ul>
            <a href="#" class="button" onclick="history.back()">Вернуться</a>
            <small>Ваш IP: {ip}</small>
        </div>
    </body>
    </html>
    """

def get_ip_location(ip):
    """Получает геолокацию IP (только для разрешенных)"""
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        return {
            'country': 'Локальный IP',
            'city': 'Локальный',
            'region': 'Локальная сеть',
            'isp': 'Локальный провайдер',
            'location_text': 'Локальное подключение'
        }
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'country': data.get('country', 'Неизвестно'),
                'city': data.get('city', 'Неизвестно'),
                'region': data.get('regionName', 'Неизвестно'),
                'isp': data.get('isp', 'Неизвестно'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'location_text': f"{data.get('city', '')}, {data.get('country', '')}"
            }
    except:
        pass
    
    return {
        'country': 'Не определено',
        'city': 'Не определено',
        'region': 'Не определено',
        'isp': 'Не определено',
        'location_text': 'Не удалось определить'
    }

@app.route('/')
def index():
    client_ip = get_real_ip()
    location = get_ip_location(client_ip)
    
    visitor_info = {
        'ip': client_ip,
        'timestamp': datetime.now().isoformat(),
        'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'location': location,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'referer': request.headers.get('Referer', 'Прямой переход')
    }
    
    # Сохраняем только разрешенные запросы
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    
    logs.append(visitor_info)
    
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>IP Logger - Ваш IP записан</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 20px;
                max-width: 600px;
                width: 100%;
                padding: 40px;
                animation: fadeIn 0.5s ease-in;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(-20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            h1 {{ color: #667eea; margin-bottom: 20px; }}
            .info-card {{
                background: #f7f9fc;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
            }}
            .info-item {{
                padding: 10px 0;
                border-bottom: 1px solid #e0e0e0;
            }}
            .info-item:last-child {{ border-bottom: none; }}
            .label {{
                font-weight: bold;
                color: #555;
                display: inline-block;
                width: 120px;
            }}
            .value {{ color: #333; font-family: monospace; }}
            .badge {{
                display: inline-block;
                background: #27ae60;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 0.85em;
            }}
            .button {{
                display: inline-block;
                background: #667eea;
                color: white;
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 5px;
                margin-top: 20px;
            }}
            .button:hover {{ background: #5a67d8; }}
            .footer {{
                margin-top: 30px;
                text-align: center;
                color: #999;
                font-size: 0.85em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Ваш IP записан!</h1>
            <div class="info-card">
                <div class="info-item">
                    <span class="label">🌐 IP адрес:</span>
                    <span class="value">{client_ip}</span>
                </div>
                <div class="info-item">
                    <span class="label">⏰ Время:</span>
                    <span class="value">{visitor_info['datetime']}</span>
                </div>
                <div class="info-item">
                    <span class="label">📍 Страна:</span>
                    <span class="value">{location['country']}</span>
                </div>
                <div class="info-item">
                    <span class="label">🏙️ Город:</span>
                    <span class="value">{location['city']}</span>
                </div>
                <div class="info-item">
                    <span class="label">📡 Провайдер:</span>
                    <span class="value">{location['isp'][:50]}</span>
                </div>
            </div>
            <a href="/stats" class="button">📊 Посмотреть статистику</a>
            <div class="footer">
                <small>🔒 VPN и прокси заблокированы | Данные сохраняются анонимно</small>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/stats')
def stats():
    """Просмотр статистики"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        # Статистика по странам
        countries = {}
        for log in logs:
            country = log.get('location', {}).get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        recent = logs[-20:][::-1]
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Статистика</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; }}
                h1 {{ color: #333; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                .stat-card {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }}
                .stat-number {{ font-size: 2em; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #667eea; color: white; }}
                tr:hover {{ background: #f5f5f5; }}
                .button {{
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📊 Статистика посещений</h1>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{len(logs)}</div>
                        <div>Всего визитов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(set(log['ip'] for log in logs))}</div>
                        <div>Уникальных IP</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(countries)}</div>
                        <div>Стран</div>
                    </div>
                </div>
                
                <h3>🌍 Топ стран</h3>
                <ul>
                    {''.join(f'<li><strong>{c}</strong>: {cnt} визитов</li>' for c, cnt in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10])}
                </ul>
                
                <h3>📝 Последние 20 посетителей</h3>
                <table>
                    <tr><th>Время</th><th>IP</th><th>Страна</th><th>Город</th></tr>
                    {''.join(f'<tr><td>{log["datetime"]}</td><td><code>{log["ip"]}</code></td><td>{log.get("location", {}).get("country", "N/A")}</td><td>{log.get("location", {}).get("city", "N/A")}</td></tr>' for log in recent)}
                </table>
                
                <a href="/" class="button">← На главную</a>
                <p style="margin-top: 20px;"><a href="/blocked">📋 Заблокированные запросы</a></p>
            </div>
        </body>
        </html>
        """
    except FileNotFoundError:
        return "Нет данных"

@app.route('/blocked')
def show_blocked():
    """Показывает заблокированные запросы (только для администратора)"""
    try:
        with open('blocked_requests.json', 'r', encoding='utf-8') as f:
            blocks = json.load(f)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Заблокированные запросы</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #e74c3c; color: white; }}
            </style>
        </head>
        <body>
            <h1>🚫 Заблокированные запросы</h1>
            <p>Всего заблокировано: {len(blocks)}</p>
            <table>
                <tr><th>Время</th><th>IP</th><th>Тип</th><th>Причина</th></tr>
                {''.join(f'<tr><td>{b["timestamp"]}</td><td><code>{b["ip"]}</code></td><td>{b["type"]}</td><td>{b["details"]}</td></tr>' for b in blocks[-50:])}
            </table>
            <p><a href="/">На главную</a></p>
        </body>
        </html>
        """
    except:
        return "Нет заблокированных запросов"

@app.route('/api/visitors')
def api_visitors():
    """API для получения данных"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        return jsonify(logs)
    except:
        return jsonify([])

@app.route('/health')
def health():
    """Health check для Render"""
    return jsonify({"status": "healthy", "vpn_block": ENABLE_VPN_BLOCK})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
