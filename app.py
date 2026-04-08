from flask import Flask, request, jsonify
from datetime import datetime
import requests
import json
import os

app = Flask(__name__)

# Используем переменную окружения для файла логов (для Render)
LOG_FILE = os.environ.get('LOG_FILE', 'visitors.json')

def get_ip_location(ip):
    """Получает геолокацию IP через бесплатный API"""
    # Пропускаем локальные IP
    if ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                     '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
                     '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', 
                     '172.29.', '172.30.', '172.31.', 'localhost', '::1')):
        return {
            'country': 'Локальный IP',
            'city': 'Локальный',
            'region': 'Локальная сеть',
            'isp': 'Локальный провайдер',
            'location_text': 'Локальное подключение'
        }
    
    try:
        # Используем бесплатный API ip-api.com
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            location = {
                'country': data.get('country', 'Неизвестно'),
                'city': data.get('city', 'Неизвестно'),
                'region': data.get('regionName', 'Неизвестно'),
                'isp': data.get('isp', 'Неизвестно'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'location_text': f"{data.get('city', '')}, {data.get('country', '')}"
            }
            return location
        else:
            return {
                'country': 'Не определено',
                'city': 'Не определено',
                'region': 'Не определено',
                'isp': 'Не определено',
                'location_text': 'Не удалось определить'
            }
    except Exception as e:
        print(f"Ошибка получения геолокации: {e}")
        return {
            'country': 'Ошибка',
            'city': 'Ошибка',
            'region': 'Ошибка',
            'isp': 'Ошибка',
            'location_text': 'Ошибка определения'
        }

@app.route('/')
def index():
    visitor_ip = request.remote_addr
    
    # Получаем реальный IP, если за прокси
    if request.headers.get('X-Forwarded-For'):
        visitor_ip = request.headers.get('X-Forwarded-For').split(',')[0]
    
    # Получаем информацию о местоположении
    location = get_ip_location(visitor_ip)
    
    # Получаем информацию о браузере
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Собираем данные
    visitor_info = {
        'ip': visitor_ip,
        'timestamp': datetime.now().isoformat(),
        'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'location': location,
        'user_agent': user_agent,
        'referer': request.headers.get('Referer', 'Прямой переход')
    }
    
    # Сохраняем в JSON файл
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    
    logs.append(visitor_info)
    
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)
    
    # Создаем красивую HTML страницу
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>IP Logger - Ваш IP записан</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
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
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 600px;
                width: 100%;
                padding: 40px;
                animation: fadeIn 0.5s ease-in;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(-20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            h1 {{
                color: #667eea;
                margin-bottom: 20px;
                font-size: 2em;
            }}
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
            .info-item:last-child {{
                border-bottom: none;
            }}
            .label {{
                font-weight: bold;
                color: #555;
                display: inline-block;
                width: 120px;
            }}
            .value {{
                color: #333;
                font-family: 'Courier New', monospace;
            }}
            .badge {{
                display: inline-block;
                background: #667eea;
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
                transition: background 0.3s;
            }}
            .button:hover {{
                background: #5a67d8;
            }}
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
                    <span class="value">{visitor_ip}</span>
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
                    <span class="value">{location['isp']}</span>
                </div>
            </div>
            <a href="/stats" class="button">📊 Посмотреть статистику</a>
            <div class="footer">
                <small>Данные сохраняются анонимно</small>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/stats')
def stats():
    """Просмотр статистики в таблице"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        # Группировка по странам
        countries = {}
        for log in logs:
            country = log.get('location', {}).get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        # Последние 10 посетителей
        recent = logs[-10:][::-1]
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Статистика посещений</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: #f5f5f5;
                    padding: 20px;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    padding: 30px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 { color: #333; margin-bottom: 20px; }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                }
                .stat-number {
                    font-size: 2.5em;
                    font-weight: bold;
                }
                .stat-label {
                    font-size: 0.9em;
                    opacity: 0.9;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background: #667eea;
                    color: white;
                }
                tr:hover {
                    background: #f5f5f5;
                }
                .button {
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin-top: 20px;
                }
                .country-list {
                    background: #f7f9fc;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                }
                .country-item {
                    padding: 5px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📊 Статистика посещений</h1>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">""" + str(len(logs)) + """</div>
                        <div class="stat-label">Всего визитов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">""" + str(len(set(log['ip'] for log in logs))) + """</div>
                        <div class="stat-label">Уникальных IP</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">""" + str(len(countries)) + """</div>
                        <div class="stat-label">Стран</div>
                    </div>
                </div>
                
                <div class="country-list">
                    <h3>🌍 Посетители по странам</h3>
        """
        
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]:
            html += f'<div class="country-item"><strong>{country}</strong>: {count} визитов</div>'
        
        html += """
                </div>
                
                <h3>📝 Последние 10 посетителей</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>IP</th>
                            <th>Страна</th>
                            <th>Город</th>
                            <th>Провайдер</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for log in recent:
            location = log.get('location', {})
            if isinstance(location, dict):
                country = location.get('country', 'N/A')
                city = location.get('city', 'N/A')
                isp = location.get('isp', 'N/A')[:30]
            else:
                country = city = isp = 'N/A'
            
            html += f"""
                        <tr>
                            <td>{log.get('datetime', log.get('timestamp', 'N/A'))}</td>
                            <td><code>{log['ip']}</code></td>
                            <td>{country}</td>
                            <td>{city}</td>
                            <td>{isp}</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
                
                <a href="/" class="button">← На главную</a>
            </div>
        </body>
        </html>
        """
        
        return html
    except FileNotFoundError:
        return "Нет данных. Перейдите на главную страницу, чтобы создать первую запись."

@app.route('/api/visitors')
def api_visitors():
    """API для получения данных в JSON формате"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        return jsonify(logs)
    except FileNotFoundError:
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
