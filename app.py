from flask import Flask, request, abort
from datetime import datetime
import requests
import json
import os
import re

app = Flask(__name__)

# ============= КОНФИГУРАЦИЯ ИЗ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ =============
SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', None)
ENABLE_VPN_BLOCK = os.environ.get('ENABLE_VPN_BLOCK', 'true').lower() == 'true'
LOG_FILE = os.environ.get('LOG_FILE', 'visitors.log')
BLOCKED_LOG_FILE = 'blocked_requests.log'

# Проверка наличия секретного ключа
if not SECRET_KEY:
    print("=" * 60)
    print("⚠️  ВНИМАНИЕ: ADMIN_SECRET_KEY не задан в переменных окружения!")
    print("⚠️  Добавьте переменную ADMIN_SECRET_KEY в настройках Render")
    print("⚠️  Использую временный ключ - ИЗМЕНИТЕ ЕГО!")
    print("=" * 60)
    SECRET_KEY = "CHANGE_ME_IN_RENDER_ENV"

# ============= СПИСКИ ДЛЯ БЛОКИРОВКИ =============
BLOCKED_ASNS = {
    'AS13335', 'AS16509', 'AS15169', 'AS8075', 'AS20473',
    'AS16276', 'AS14061', 'AS63949', 'AS14618', 'AS200019',
    'AS36459', 'AS54113', 'AS20940', 'AS60068', 'AS53850'
}

SUSPICIOUS_KEYWORDS = [
    'vpn', 'hosting', 'cloud', 'data center', 'proxy', 'server', 
    'virtual', 'dedicated', 'vps', 'colo', 'rack', 'host', 'cloudflare',
    'digitalocean', 'aws', 'amazon', 'azure', 'google cloud', 'linode',
    'vultr', 'ovh', 'hetzner', 'namecheap', 'godaddy', 'vpn', 'proxy'
]

BLOCKED_USER_AGENTS = [
    'python-requests', 'curl', 'wget', 'go-http-client', 'java', 
    'perl', 'ruby', 'scrapy', 'httpx', 'aiohttp', 'okhttp',
    'bot', 'crawler', 'spider', 'scanner', 'nmap', 'masscan',
    'zgrab', 'httpie', 'rest-client', 'axios', 'node-fetch'
]

# ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============
def get_real_ip():
    """Получает реальный IP клиента за прокси"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    return request.remote_addr

def log_to_file(ip, status, details=""):
    """Записывает информацию о посетителе в лог-файл"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_agent = request.headers.get('User-Agent', 'Unknown')
    path = request.path
    method = request.method
    
    # Получаем страну (если есть)
    country = "Unknown"
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        data = response.json()
        if data.get('status') == 'success':
            country = data.get('countryCode', 'Unknown')
    except:
        pass
    
    log_entry = f"[{timestamp}] {status} | IP: {ip} | Country: {country} | Method: {method} | Path: {path} | UA: {user_agent[:80]}"
    if details:
        log_entry += f" | {details}"
    log_entry += "\n"
    
    filename = BLOCKED_LOG_FILE if status == "BLOCKED" else LOG_FILE
    
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Ошибка записи лога: {e}")

def is_vpn_or_hosting(ip):
    """Проверяет IP через ip-api.com на принадлежность к VPN/хостингу"""
    if not ENABLE_VPN_BLOCK:
        return False, None
    
    if ip.startswith(('127.', '192.168.', '10.', '172.')):
        return False, None
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            # Используем специальные поля API для определения прокси/хостинга [citation:1]
            if data.get('proxy') or data.get('hosting'):
                return True, f"IP is proxy or hosting (proxy={data.get('proxy')}, hosting={data.get('hosting')})"
            
            # Дополнительная проверка по ASN хостингов
            hosting_asns = ['AS13335', 'AS16509', 'AS15169', 'AS20473', 'AS14061']
            asn = data.get('as', '').split()[0] if data.get('as') else ''
            if asn in hosting_asns:
                return True, f"Hosting ASN detected: {asn}"
                
        return False, None
    except:
        return False, None

def check_user_agent():
    """Проверяет User-Agent на ботов (более точная)"""
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Пустой User-Agent - почти всегда бот
    if not user_agent or user_agent == 'unknown':
        return True, "Empty User-Agent"
    
    # Слишком короткий UA (меньше 20 символов) - подозрительно
    if len(user_agent) < 20:
        return True, f"Suspicious short User-Agent ({len(user_agent)} chars)"
    
    # Список ботов (только явные)
    BOT_KEYWORDS = [
        'python-requests', 'curl', 'wget', 'go-http-client', 
        'java', 'perl', 'ruby', 'scrapy', 'httpx', 'okhttp',
        'bot', 'crawler', 'scanner', 'nmap', 'masscan', 'zgrab'
    ]
    
    for bot in BOT_KEYWORDS:
        if bot in user_agent:
            return True, f"Bot detected: {bot}"
    
    # Проверка на нормальные браузеры (не блокируем, а пропускаем)
    BROWSER_KEYWORDS = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'mobile', 'android', 'iphone', 'ipad']
    
    # Если нет признаков браузера и длина UA нормальная - может быть бот
    if not any(browser in user_agent for browser in BROWSER_KEYWORDS):
        # Но не блокируем, только логируем как подозрительный
        return False, None  # Пропускаем, но не блокируем
    
    return False, None

def check_missing_headers():
    """Проверяет наличие обязательных браузерных заголовков (более мягкая проверка)"""
    # Браузеры почти всегда отправляют Accept
    if not request.headers.get('Accept'):
        return True, "Missing Accept header"
    
    # Accept-Language обычно есть у браузеров, но не всегда у мобильных
    # Сделаем эту проверку опциональной
    if not request.headers.get('Accept-Language'):
        # Не блокируем сразу, только если нет и других признаков
        if not request.headers.get('Accept') and not request.headers.get('User-Agent'):
            return True, "Missing browser headers"
    
    # Убираем проверку Connection - она не критична
    return False, None

# ============= ОСНОВНАЯ ПРОВЕРКА =============
@app.before_request
def security_check():
    """Проверка безопасности и логгирование"""
    # Пропускаем health check и статические файлы
    if request.path in ['/health', '/robots.txt', '/favicon.ico']:
        return None
    
    # Пропускаем админские маршруты
    if request.path.startswith(f'/{SECRET_KEY}'):
        return None
    
    client_ip = get_real_ip()
    
    # Проверка на отсутствие браузерных заголовков
    is_missing, missing_reason = check_missing_headers()
    if is_missing:
        log_to_file(client_ip, "BLOCKED", missing_reason)
        abort(404)
    
    # Проверка User-Agent
    is_bot, bot_reason = check_user_agent()
    if is_bot:
        log_to_file(client_ip, "BLOCKED", bot_reason)
        abort(404)
    
    # Проверка на VPN
    is_vpn, vpn_reason = is_vpn_or_hosting(client_ip)
    if is_vpn:
        log_to_file(client_ip, "BLOCKED", vpn_reason)
        abort(404)
    
    # Логгируем успешный запрос
    log_to_file(client_ip, "VISITED")
    
    # Всегда возвращаем 404 для всех обычных путей
    abort(404)

# ============= СТРАНИЦА 404 =============
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
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            .container {
                text-align: center;
                max-width: 600px;
                animation: fadeIn 0.5s ease-out;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            h1 {
                font-size: 120px;
                font-weight: 700;
                margin: 0;
                background: linear-gradient(135deg, #e74c3c, #c0392b);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
            .glitch {
                font-size: 120px;
                font-weight: 700;
                position: relative;
                margin: 0;
            }
            p {
                font-size: 18px;
                color: #888;
                margin: 20px 0;
                line-height: 1.6;
            }
            .error-code {
                font-family: 'Courier New', monospace;
                color: #555;
                margin-top: 30px;
                font-size: 14px;
                border-top: 1px solid #333;
                padding-top: 20px;
                display: inline-block;
            }
            @media (max-width: 768px) {
                h1 { font-size: 80px; }
                .glitch { font-size: 80px; }
                p { font-size: 14px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="glitch">
                <h1>404</h1>
            </div>
            <p>
                The page you are looking for<br>
                does not exist or has been moved.
            </p>
            <div class="error-code">
                ERROR_404_NOT_FOUND
            </div>
        </div>
    </body>
    </html>
    """, 404

# ============= АДМИНСКИЕ МАРШРУТЫ (СКРЫТЫЕ) =============
@app.route(f'/{SECRET_KEY}')
def admin_panel():
    """Скрытая админ-панель"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Admin Panel - IP Logger</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #1e1e1e;
                min-height: 100vh;
                padding: 40px 20px;
            }}
            .container {{
                max-width: 800px;
                margin: 0 auto;
            }}
            h1 {{
                color: #4ec9b0;
                margin-bottom: 30px;
                text-align: center;
                font-size: 2.5em;
            }}
            .menu {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .card {{
                background: #2d2d30;
                border-radius: 10px;
                padding: 30px;
                text-align: center;
                transition: transform 0.2s, box-shadow 0.2s;
                cursor: pointer;
            }}
            .card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }}
            .card-icon {{
                font-size: 48px;
                margin-bottom: 15px;
            }}
            .card-title {{
                color: #fff;
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 10px;
            }}
            .card-desc {{
                color: #888;
                font-size: 14px;
            }}
            a {{
                text-decoration: none;
            }}
            .stats {{
                background: #2d2d30;
                border-radius: 10px;
                padding: 20px;
                margin-top: 20px;
            }}
            .stats h3 {{
                color: #4ec9b0;
                margin-bottom: 15px;
            }}
            .stat-item {{
                display: flex;
                justify-content: space-between;
                padding: 10px 0;
                border-bottom: 1px solid #3e3e42;
                color: #d4d4d4;
            }}
            .stat-item:last-child {{
                border-bottom: none;
            }}
            .stat-label {{
                font-weight: 600;
            }}
            .stat-value {{
                font-family: monospace;
                color: #4ec9b0;
            }}
            .footer {{
                text-align: center;
                margin-top: 30px;
                color: #555;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Admin Dashboard</h1>
            <div class="menu">
                <a href="/{SECRET_KEY}/logs">
                    <div class="card">
                        <div class="card-icon">📋</div>
                        <div class="card-title">View Logs</div>
                        <div class="card-desc">All visitor records</div>
                    </div>
                </a>
                <a href="/{SECRET_KEY}/stats">
                    <div class="card">
                        <div class="card-icon">📊</div>
                        <div class="card-title">Statistics</div>
                        <div class="card-desc">Analytics & metrics</div>
                    </div>
                </a>
                <a href="/{SECRET_KEY}/blocked">
                    <div class="card">
                        <div class="card-icon">🚫</div>
                        <div class="card-title">Blocked</div>
                        <div class="card-desc">VPN & bot attempts</div>
                    </div>
                </a>
                <a href="/{SECRET_KEY}/clear" onclick="return confirm('Are you sure? This will delete ALL logs!')">
                    <div class="card">
                        <div class="card-icon">🗑️</div>
                        <div class="card-title">Clear Logs</div>
                        <div class="card-desc">Delete all records</div>
                    </div>
                </a>
            </div>
            <div class="footer">
                🔒 Secure access | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
    </body>
    </html>
    """

@app.route(f'/{SECRET_KEY}/logs')
def view_logs():
    """Просмотр всех логов"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.read()
        
        total_lines = len([l for l in logs.split('\n') if l.strip()]) if logs else 0
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Logs - IP Logger</title>
            <style>
                body {{ font-family: 'Courier New', monospace; margin: 0; background: #1e1e1e; color: #d4d4d4; }}
                .header {{ background: #2d2d30; padding: 20px; border-bottom: 1px solid #3e3e42; }}
                h1 {{ color: #4ec9b0; margin: 0; }}
                .stats {{ color: #888; margin-top: 10px; }}
                .content {{ padding: 20px; }}
                pre {{ background: #252526; padding: 20px; border-radius: 5px; overflow-x: auto; margin: 0; }}
                .button {{
                    display: inline-block;
                    background: #0e639c;
                    color: white;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    margin-right: 10px;
                }}
                .button:hover {{ background: #1177bb; }}
                .nav {{ margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📋 Visitor Logs</h1>
                <div class="stats">Total entries: {total_lines}</div>
            </div>
            <div class="content">
                <div class="nav">
                    <a href="/{SECRET_KEY}" class="button">← Back to Admin</a>
                    <a href="/{SECRET_KEY}/stats" class="button">📊 Statistics</a>
                    <a href="/{SECRET_KEY}/blocked" class="button">🚫 Blocked</a>
                </div>
                <pre>{logs if logs else "No logs yet. Visitors will appear here when they visit the site."}</pre>
            </div>
        </body>
        </html>
        """
    except FileNotFoundError:
        return f"""
        <html>
        <body style="background: #1e1e1e; color: #d4d4d4; font-family: monospace; padding: 20px;">
            <h1>📋 Logs</h1>
            <p>No logs yet. Visitors will appear here when they visit the site.</p>
            <a href="/{SECRET_KEY}" class="button">← Back</a>
        </body>
        </html>
        """

@app.route(f'/{SECRET_KEY}/stats')
def view_stats():
    """Статистика посещений"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Парсим логи
        ips = {}
        countries = {}
        dates = {}
        user_agents = {}
        
        for line in lines:
            if 'VISITED' in line:
                # Извлекаем IP
                ip_match = re.search(r'IP: ([\d\.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    ips[ip] = ips.get(ip, 0) + 1
                
                # Извлекаем страну
                country_match = re.search(r'Country: (\w+)', line)
                if country_match:
                    country = country_match.group(1)
                    countries[country] = countries.get(country, 0) + 1
                
                # Извлекаем дату
                if line.startswith('['):
                    date = line[1:11]
                    dates[date] = dates.get(date, 0) + 1
        
        total_visits = len([l for l in lines if 'VISITED' in l])
        unique_ips = len(ips)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Statistics - IP Logger</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #1e1e1e; color: #d4d4d4; }}
                .header {{ background: #2d2d30; padding: 20px; border-bottom: 1px solid #3e3e42; }}
                h1 {{ color: #4ec9b0; margin: 0; }}
                .content {{ padding: 20px; max-width: 1200px; margin: 0 auto; }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                .stat-card {{
                    background: #2d2d30;
                    padding: 25px;
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
                    padding: 12px;
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
                    padding: 8px 16px;
                    border-radius: 4px;
                    margin-right: 10px;
                }}
                .button:hover {{ background: #1177bb; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Statistics</h1>
            </div>
            <div class="content">
                <div style="margin-bottom: 20px;">
                    <a href="/{SECRET_KEY}" class="button">← Back to Admin</a>
                    <a href="/{SECRET_KEY}/logs" class="button">📋 View Logs</a>
                </div>
                
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
                        <div class="stat-label">Days Active</div>
                    </div>
                </div>
                
                <h3>🌍 Top Countries</h3>
                <table>
                    <tr><th>Country</th><th>Visits</th></tr>
                    {''.join(f'<tr><td>{c if c != "Unknown" else "❓ Unknown"}</td><td>{cnt}</td></tr>' for c, cnt in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10])}
                </table>
                
                <h3>🔝 Top IPs</h3>
                <table>
                    <tr><th>IP Address</th><th>Visits</th></tr>
                    {''.join(f'<tr><td><code>{ip}</code></td><td>{cnt}</td></tr>' for ip, cnt in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])}
                </table>
                
                <h3>📅 Recent Activity</h3>
                <table>
                    <tr><th>Date</th><th>Visits</th></tr>
                    {''.join(f'<tr><td>{date}</td><td>{cnt}</td></tr>' for date, cnt in sorted(dates.items(), reverse=True)[:10])}
                </table>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error loading statistics: {e}"

@app.route(f'/{SECRET_KEY}/blocked')
def view_blocked():
    """Просмотр заблокированных запросов"""
    try:
        with open(BLOCKED_LOG_FILE, 'r', encoding='utf-8') as f:
            blocked = f.read()
        
        total_blocked = len([l for l in blocked.split('\n') if l.strip()]) if blocked else 0
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Blocked - IP Logger</title>
            <style>
                body {{ font-family: 'Courier New', monospace; margin: 0; background: #1e1e1e; color: #d4d4d4; }}
                .header {{ background: #2d2d30; padding: 20px; border-bottom: 1px solid #3e3e42; }}
                h1 {{ color: #f48771; margin: 0; }}
                .stats {{ color: #888; margin-top: 10px; }}
                .content {{ padding: 20px; }}
                pre {{ background: #252526; padding: 20px; border-radius: 5px; overflow-x: auto; }}
                .button {{
                    display: inline-block;
                    background: #0e639c;
                    color: white;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    margin-right: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚫 Blocked Requests</h1>
                <div class="stats">Total blocked: {total_blocked}</div>
            </div>
            <div class="content">
                <a href="/{SECRET_KEY}" class="button">← Back to Admin</a>
                <pre>{blocked if blocked else "No blocked requests yet. VPN and bots will appear here."}</pre>
            </div>
        </body>
        </html>
        """
    except FileNotFoundError:
        return f"""
        <html>
        <body style="background: #1e1e1e; color: #d4d4d4; font-family: monospace; padding: 20px;">
            <h1>🚫 Blocked Requests</h1>
            <p>No blocked requests yet.</p>
            <a href="/{SECRET_KEY}" class="button">← Back</a>
        </body>
        </html>
        """

@app.route(f'/{SECRET_KEY}/clear')
def clear_logs():
    """Очистка логов"""
    try:
        open(LOG_FILE, 'w').close()
        open(BLOCKED_LOG_FILE, 'w').close()
        return f"""
        <html>
        <body style="background: #1e1e1e; color: #d4d4d4; font-family: monospace; padding: 20px;">
            <h1>✅ Logs Cleared</h1>
            <p>All log files have been cleared successfully.</p>
            <a href="/{SECRET_KEY}" class="button">← Back to Admin</a>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error clearing logs: {e}"

# ============= HEALTH CHECK ДЛЯ RENDER =============
@app.route('/health')
def health():
    """Health check endpoint для Render"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}, 200

# ============= ЗАПУСК ПРИЛОЖЕНИЯ =============
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("=" * 60)
    print("🚀 IP Logger Server Started")
    print("=" * 60)
    print(f"📍 Port: {port}")
    print(f"🔐 Admin Panel: /{SECRET_KEY}")
    print(f"📝 Log file: {LOG_FILE}")
    print(f"🚫 VPN Block: {ENABLE_VPN_BLOCK}")
    print("=" * 60)
    print("⚠️  All visitors will see 404 error")
    print("⚠️  IPs are logged without their knowledge")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=False)
