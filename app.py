from flask import Flask, request, abort
from datetime import datetime
import requests
import json
import os
from functools import wraps

app = Flask(__name__)

# Конфигурация
LOG_FILE = os.environ.get('LOG_FILE', 'visitors.log')  # Текстовый файл для логов
BLOCKED_LOG_FILE = 'blocked_requests.log'  # Логи заблокированных
ENABLE_VPN_BLOCK = os.environ.get('ENABLE_VPN_BLOCK', 'true').lower() == 'true'

# Список ASN дата-центров и хостингов
BLOCKED_ASNS = {
    'AS13335', 'AS16509', 'AS15169', 'AS8075', 'AS20473',
    'AS16276', 'AS14061', 'AS63949', 'AS14618', 'AS200019',
    'AS36459', 'AS54113', 'AS20940',
}

# Ключевые слова VPN/хостингов
SUSPICIOUS_KEYWORDS = [
    'vpn', 'hosting', 'cloud', 'data center', 'proxy', 'server', 
    'virtual', 'dedicated', 'vps', 'colo', 'rack', 'host', 'cloudflare',
    'digitalocean', 'aws', 'amazon', 'azure', 'google cloud', 'linode',
    'vultr', 'ovh', 'hetzner'
]

# Подозрительные User-Agent
BLOCKED_USER_AGENTS = [
    'python-requests', 'curl', 'wget', 'go-http-client', 'java', 
    'perl', 'ruby', 'scrapy', 'httpx', 'aiohttp', 'okhttp',
    'bot', 'crawler', 'spider', 'scanner'
]

def get_real_ip():
    """Получает реальный IP клиента за прокси"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def log_to_file(ip, status, details=""):
    """Записывает информацию о посетителе в лог-файл"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    path = request.path
    
    log_entry = f"[{timestamp}] IP: {ip} | Status: {status} | Path: {path} | UA: {user_agent[:100]}"
    if details:
        log_entry += f" | Details: {details}"
    log_entry += "\n"
    
    # Выбираем файл для записи
    if status == "BLOCKED":
        filename = BLOCKED_LOG_FILE
    else:
        filename = LOG_FILE
    
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Ошибка записи лога: {e}")

def is_vpn_or_hosting(ip):
    """Проверяет, принадлежит ли IP VPN сервису или хостингу"""
    if not ENABLE_VPN_BLOCK:
        return False, None
    
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        return False, None
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            asn = data.get('as', '').split()[0] if data.get('as') else ''
            org = data.get('org', '').lower()
            isp = data.get('isp', '').lower()
            
            if asn in BLOCKED_ASNS:
                return True, f"Datacenter blocked (ASN: {asn})"
            
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in org or keyword in isp:
                    return True, f"VPN/Hosting detected: {org}"
        return False, None
    except:
        return False, None

def check_user_agent():
    """Проверяет User-Agent на ботов"""
    user_agent = request.headers.get('User-Agent', '').lower()
    for bot in BLOCKED_USER_AGENTS:
        if bot in user_agent:
            return True, f"Bot detected: {bot}"
    if not user_agent:
        return True, "Missing User-Agent"
    return False, None

@app.before_request
def security_check():
    """Проверка безопасности и логгирование"""
    client_ip = get_real_ip()
    
    # Проверка на ботов
    is_bot, bot_reason = check_user_agent()
    if is_bot:
        log_to_file(client_ip, "BLOCKED", bot_reason)
        abort(404)  # Возвращаем 404 вместо страницы блокировки
    
    # Проверка на VPN
    is_vpn, vpn_reason = is_vpn_or_hosting(client_ip)
    if is_vpn:
        log_to_file(client_ip, "BLOCKED", vpn_reason)
        abort(404)  # Возвращаем 404 вместо страницы блокировки
    
    # Логгируем успешный запрос
    log_to_file(client_ip, "VISITED")
    
    # Всегда возвращаем 404 для всех путей
    # (кроме специальных админских, если нужно)
    if request.path not in ['/admin', '/stats', '/logs']:
        abort(404)

@app.errorhandler(404)
def page_not_found(e):
    """Страница 404 для всех посетителей"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>404 - Page Not Found</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #1a1a1a;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                margin: 0;
                padding: 20px;
            }
            .container {
                text-align: center;
                color: #fff;
            }
            h1 {
                font-size: 120px;
                margin: 0;
                color: #e74c3c;
                text-shadow: 4px 4px 0px #c0392b;
            }
            p {
                font-size: 20px;
                color: #888;
            }
            .error-code {
                font-family: monospace;
                color: #555;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>404</h1>
            <p>Page not found</p>
            <div class="error-code">ERROR_404</div>
        </div>
    </body>
    </html>
    """, 404

# ============= АДМИНСКИЕ МАРШРУТЫ (скрытые, для просмотра логов) =============
# ВНИМАНИЕ: Эти страницы доступны только если знать секретный путь!
# Измените "admin123" на свой секретный ключ

SECRET_KEY = "iPlo-Gg-in-N-gJoS123"  # ИЗМЕНИТЕ ЭТО НА СВОЙ СЕКРЕТНЫЙ КЛЮЧ!

@app.route(f'/{SECRET_KEY}/logs')
def view_logs():
    """Просмотр всех логов (скрытая страница)"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.read()
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Logs - IP Logger</title>
            <style>
                body {{ font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }}
                h1 {{ color: #4ec9b0; }}
                pre {{ background: #252526; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                .stats {{ background: #2d2d30; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .button {{
                    display: inline-block;
                    background: #0e639c;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin: 10px 5px;
                }}
                .button:hover {{ background: #1177bb; }}
            </style>
        </head>
        <body>
            <h1>📋 Visitor Logs</h1>
            <div class="stats">
                <strong>Total entries:</strong> {len(logs.strip().split(chr(10))) if logs else 0}
            </div>
            <div style="margin: 20px 0;">
                <a href="/{SECRET_KEY}/stats" class="button">📊 Statistics</a>
                <a href="/{SECRET_KEY}/blocked" class="button">🚫 Blocked</a>
                <a href="/{SECRET_KEY}/clear" class="button" onclick="return confirm('Clear all logs?')">🗑️ Clear Logs</a>
            </div>
            <pre>{logs if logs else "No logs yet"}</pre>
        </body>
        </html>
        """
    except FileNotFoundError:
        return "No logs yet"

@app.route(f'/{SECRET_KEY}/stats')
def view_stats():
    """Статистика посещений (скрытая страница)"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Парсим логи
        ips = {}
        dates = {}
        user_agents = {}
        
        for line in lines:
            if 'IP:' in line and 'VISITED' in line:
                # Извлекаем IP
                ip_start = line.find('IP:') + 4
                ip_end = line.find(' |', ip_start)
                if ip_end == -1:
                    ip_end = len(line)
                ip = line[ip_start:ip_end].strip()
                ips[ip] = ips.get(ip, 0) + 1
                
                # Извлекаем дату
                date = line[1:11] if len(line) > 10 else "Unknown"
                dates[date] = dates.get(date, 0) + 1
                
                # Извлекаем User-Agent
                ua_start = line.find('UA:') + 4
                if ua_start > 4:
                    ua = line[ua_start:].strip()[:50]
                    user_agents[ua] = user_agents.get(ua, 0) + 1
        
        total_visits = len([l for l in lines if 'VISITED' in l])
        unique_ips = len(ips)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Statistics - IP Logger</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }}
                h1 {{ color: #4ec9b0; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .stat-card {{
                    background: #2d2d30;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #4ec9b0;
                }}
                .stat-label {{
                    color: #888;
                    margin-top: 10px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #3e3e42;
                }}
                th {{
                    background: #0e639c;
                    color: white;
                }}
                .button {{
                    display: inline-block;
                    background: #0e639c;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin: 10px 5px;
                }}
                .button:hover {{ background: #1177bb; }}
            </style>
        </head>
        <body>
            <h1>📊 Statistics</h1>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_visits}</div>
                    <div class="stat-label">Total Visits</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{unique_ips}</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(dates)}</div>
                    <div class="stat-label">Days</div>
                </div>
            </div>
            
            <h3>🌍 Top IPs</h3>
            <table>
                <tr><th>IP Address</th><th>Visits</th></tr>
                {''.join(f'<tr><td><code>{ip}</code></td><td>{count}</td></tr>' for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])}
            </table>
            
            <h3>📅 Visits by Day</h3>
            <table>
                <tr><th>Date</th><th>Visits</th></tr>
                {''.join(f'<tr><td>{date}</td><td>{count}</td></tr>' for date, count in sorted(dates.items(), reverse=True)[:10])}
            </table>
            
            <div style="margin-top: 30px;">
                <a href="/{SECRET_KEY}/logs" class="button">← Back to Logs</a>
                <a href="/{SECRET_KEY}/blocked" class="button">🚫 View Blocked</a>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error: {e}"

@app.route(f'/{SECRET_KEY}/blocked')
def view_blocked():
    """Просмотр заблокированных запросов"""
    try:
        with open(BLOCKED_LOG_FILE, 'r', encoding='utf-8') as f:
            blocked = f.read()
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Blocked - IP Logger</title>
            <style>
                body {{ font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }}
                h1 {{ color: #f48771; }}
                pre {{ background: #252526; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                .button {{
                    display: inline-block;
                    background: #0e639c;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin: 10px 5px;
                }}
            </style>
        </head>
        <body>
            <h1>🚫 Blocked Requests</h1>
            <pre>{blocked if blocked else "No blocked requests"}</pre>
            <a href="/{SECRET_KEY}/logs" class="button">← Back</a>
        </body>
        </html>
        """
    except:
        return "No blocked requests"

@app.route(f'/{SECRET_KEY}/clear')
def clear_logs():
    """Очистка логов"""
    try:
        open(LOG_FILE, 'w').close()
        open(BLOCKED_LOG_FILE, 'w').close()
        return "Logs cleared! <a href='/{}'>Back</a>".format(SECRET_KEY)
    except:
        return "Error clearing logs"

@app.route(f'/{SECRET_KEY}')
def admin_panel():
    """Скрытая админ-панель"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Admin Panel</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #d4d4d4; }}
            .container {{ max-width: 600px; margin: 0 auto; text-align: center; }}
            h1 {{ color: #4ec9b0; }}
            .menu {{ margin: 30px 0; }}
            .button {{
                display: block;
                background: #0e639c;
                color: white;
                text-decoration: none;
                padding: 15px;
                margin: 10px 0;
                border-radius: 5px;
            }}
            .button:hover {{ background: #1177bb; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Admin Panel</h1>
            <div class="menu">
                <a href="/{SECRET_KEY}/logs" class="button">📋 View All Logs</a>
                <a href="/{SECRET_KEY}/stats" class="button">📊 Statistics</a>
                <a href="/{SECRET_KEY}/blocked" class="button">🚫 Blocked Requests</a>
            </div>
        </div>
    </body>
    </html>
    """

# Health check для Render
@app.route('/health')
def health():
    return {"status": "healthy"}, 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Server running on port {port}")
    print(f"Admin panel: http://localhost:{port}/{SECRET_KEY}")
    print(f"Logs are saved to: {LOG_FILE}")
    app.run(host='0.0.0.0', port=port, debug=False)
