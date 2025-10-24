# server_auth.py
"""
門限チェックシステム（Flask + SQLite + JWT）
使い方（簡単）:
1) 必要パッケージをインストール:
   pip install flask flask-cors pyjwt passlib

2) 環境変数 SECRET_KEY を設定（推奨）
   export SECRET_KEY='超強いランダム文字列'   # mac/linux
   set SECRET_KEY=超強いランダム文字列         # Windows (cmd)

3) サーバー起動:
   python server_auth.py

注意:
- 本番運用時は HTTPS を必須にしてください。
- SECRET_KEY は安全に保管してください（環境変数推奨）。
"""

from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta, time, timezone
import math
import os
import jwt
import requests
from passlib.hash import pbkdf2_sha256 as hasher

# ------------------ 設定 ------------------
DB_PATH = "curfew.db"
# 環境変数から SECRET_KEY を取得（無ければ警告してデフォルト）
# SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION") # ← この行をコメントアウト
SECRET_KEY = "my_super_secret_key_12345" # ← この行を追加（鍵の文字列は適当でOK）
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60

# 門限（サーバー時刻で判定）例：22:00
CURFEW = time(22, 0)

# 寮の座標（ここは実際の値に置き換えてください）
DORM_LAT = 35.6604
DORM_LON = 139.6178
RADIUS_KM = 0.05  # 許容半径（km）

# 管理者メールアドレス（簡易的にログ閲覧用）
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "ayakazuki0805@icloud.com")

# ------------------------------------------------

app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False

# ▼▼▼ これを追加 ▼▼▼
# / (ルートURL) にアクセスが来たら checkin.html を表示する
@app.route('/')
def serve_html():
    return send_from_directory('.', 'checkin.html')
# ▲▲▲ ここまで ▲▲▲

# ------------------ ユーティリティ ------------------
def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    # users: id, name, email, pw_hash, device_id
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email TEXT UNIQUE,
                    pw_hash TEXT,
                    device_id TEXT
                )''')
    # checkins: id, user_id, lat, lon, server_time, status
    c.execute('''CREATE TABLE IF NOT EXISTS checkins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    lat REAL,
                    lon REAL,
                    server_time TEXT,
                    status TEXT
                )''')
    db.commit()
    db.close()

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0  # km
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def generate_token(user_id):
    payload = {
        "sub": str(user_id), # <-- (1) 整数を文字列に変換
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES),
        "iat": datetime.now(timezone.utc)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
    # pyjwt>=2.x returns str; older versions bytes - ensure str
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        # 成功
        return payload
    except jwt.ExpiredSignatureError:
        # 有効期限切れ
        print("DEBUG: [Decode] Token failed: ExpiredSignatureError (有効期限切れです)")
        return None
    except jwt.InvalidIssuedAtError as e:
        # 発行時刻 (iat) が未来になっている
        print(f"DEBUG: [Decode] Token failed: InvalidIssuedAtError (発行時刻が未来です: {e})")
        return None
    except jwt.InvalidTokenError as e:
        # その他のJWT関連エラー（署名が違う、形式が不正など）
        print(f"DEBUG: [Decode] Token failed: InvalidTokenError (その他のトークンエラー: {e})")
        return None
    except Exception as e:
        # 予期せぬその他のエラー
        print(f"DEBUG: [Decode] An unexpected error occurred during decode: {e}")
        return None

def get_user_from_token():
    auth = request.headers.get('Authorization', None)

    # ▼▼▼ この行を追加 ▼▼▼
    print(f"DEBUG: [Checkin] 受信した Authorization ヘッダ: {auth}")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    token = parts[1]
    # ▼▼▼ この行を追加 ▼▼▼
    print(f"DEBUG: [Checkin] ヘッダから抽出したトークン: {token}")
    payload = decode_token(token)
    if not payload:
        return None
    
    # ▼▼▼ (2) "sub" は文字列(str)として保存されているため、整数(int)に変換して返す ▼▼▼
    try:
        # payload.get('sub') (例: "1") を int() で 整数 (例: 1) に変換
        return int(payload.get('sub'))
    except (ValueError, TypeError):
        # 変換に失敗したらNone
        return None

# ------------------ ルート（認証周り） ------------------
@app.route('/register', methods=['POST'])
def register():
    """
    例リクエストJSON:
    {
        "name": "山田太郎",
        "email": "taro@example.com",
        "password": "plain_password",
        "device_id": "端末で生成したUUID"
    }
    """
    data = request.get_json() or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    device_id = data.get('device_id')

    if not (name and email and password and device_id):
        return jsonify({"error": "name, email, password, device_id が必要です"}), 400

    pw_hash = hasher.hash(password)
    db = get_db()
    try:
        db.execute('INSERT INTO users (name, email, pw_hash, device_id) VALUES (?, ?, ?, ?)',
                   (name, email, pw_hash, device_id))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "そのメールは既に登録されています"}), 400

    return jsonify({"msg": "登録完了"}), 201

@app.route('/login', methods=['POST'])
def login():
    """
    リクエストJSON:
    { "email": "...", "password": "..." }
    レスポンス:
    { "token": "Bearer JWTトークン" }
    """
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not (email and password):
        return jsonify({"error": "email と password が必要です"}), 400

    db = get_db()
    row = db.execute('SELECT id, pw_hash FROM users WHERE email=?', (email,)).fetchone()
    if not row:
        return jsonify({"error": "ユーザーが見つかりません"}), 401

    user_id = row['id']
    pw_hash = row['pw_hash']
    if not hasher.verify(password, pw_hash):
        return jsonify({"error": "パスワード不正"}), 401

    token = generate_token(user_id)
    # ▼▼▼ この行を追加 ▼▼▼
    print(f"DEBUG: [Login] 発行したトークン: {token}")
    return jsonify({"token": token})

@app.route('/bind_device', methods=['POST'])
def bind_device():
    """
    端末バインド（再登録）: 管理者または本人が端末を変更した際に使用する想定
    JSON:
    { "email": "...", "password": "...", "new_device_id": "新しいID" }
    （簡易的に認証して device_id を更新する）
    """
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    new_device_id = data.get('new_device_id')
    if not (email and password and new_device_id):
        return jsonify({"error": "email, password, new_device_id が必要です"}), 400

    db = get_db()
    row = db.execute('SELECT id, pw_hash FROM users WHERE email=?', (email,)).fetchone()
    if not row:
        return jsonify({"error": "ユーザーが見つかりません"}), 401
    if not hasher.verify(password, row['pw_hash']):
        return jsonify({"error": "認証失敗"}), 401

    db.execute('UPDATE users SET device_id=? WHERE id=?', (new_device_id, row['id']))
    db.commit()
    return jsonify({"msg": "端末を更新しました"}), 200

# ------------------ チェックイン ------------------
@app.route('/checkin', methods=['POST'])
def checkin():
    """
    Authorization: Bearer <token> 必須
    Header: X-Device-ID: <device_id> 必須
    Body JSON:
    { "latitude": 35.66, "longitude": 139.61 }
    サーバー時刻で門限判定し DB に保存
    """
    user_id = get_user_from_token()
    if not user_id:
        return jsonify({"error": "認証エラー（トークン無効または期限切れ）"}), 401

    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({"error": "X-Device-ID ヘッダが必要です"}), 400

    db = get_db()
    row = db.execute('SELECT device_id, name FROM users WHERE id=?', (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "ユーザー不明"}), 401
    registered_device = row['device_id']
    user_name = row['name']

    if registered_device != device_id:
        return jsonify({"error": "この端末は登録されていません（device mismatch）"}), 403

    data = request.get_json() or {}
    lat = data.get('latitude')
    lon = data.get('longitude')
    if lat is None or lon is None:
        return jsonify({"error": "latitude と longitude を送ってください"}), 400

    # サーバー時刻で門限を判定（クライアント時刻は信用しない）
    now = datetime.now()
    server_time_str = now.isoformat()

    # 位置判定
    distance = haversine(DORM_LAT, DORM_LON, float(lat), float(lon))
    is_at_dorm = distance <= RADIUS_KM
    # 時刻判定（門限以前かどうか）
    now_time = now.time()
    within_curfew = (now_time <= CURFEW)

    if is_at_dorm and within_curfew:
        status = "セーフ (位置と時刻OK)"
    elif not is_at_dorm and within_curfew:
        status = "アウト (位置NG)"
    elif is_at_dorm and not within_curfew:
        status = "アウト (時刻NG)"
    else:
        status = "アウト (位置・時刻 NG)"

    # DB 保存
    db.execute('INSERT INTO checkins (user_id, lat, lon, server_time, status) VALUES (?, ?, ?, ?, ?)',
               (user_id, float(lat), float(lon), server_time_str, status))
    db.commit()

    # 実運用ではここで通知（メールやLINE等）を送ることも可能
    return jsonify({
        "user": user_name,
        "server_time": server_time_str,
        "distance_km": round(distance, 5),
        "status": status
    })

# ------------

# ------------------ 管理者用 ------------------
@app.route('/admin_logs')
def admin_logs():
    """
    管理者用ログ閲覧ページ。
    管理者のトークンで認証し、全履歴をHTMLで返す。
    """
    db = get_db()
    
    # 1. 認証 (管理者かどうかをチェック)
    try:
        user_id = get_user_from_token()
        if not user_id:
            return "認証エラー: ログインしてください", 401
            
        admin_user = db.execute('SELECT email FROM users WHERE id=?', (user_id,)).fetchone()
        
        # 設定ファイルにある ADMIN_EMAIL と一致するか確認
        if not admin_user or admin_user['email'] != ADMIN_EMAIL:
            return "権限エラー: 管理者としてログインしていません", 403
            
    except Exception as e:
        return f"認証トークン処理エラー: {e}", 401

    # 2. ログの取得 (users テーブルと結合して名前を取得)
    logs = db.execute('''
        SELECT U.name, C.lat, C.lon, C.server_time, C.status 
        FROM checkins C
        JOIN users U ON C.user_id = U.id
        ORDER BY C.id DESC
        LIMIT 100 
    ''').fetchall() # DESC = 新しい順 / LIMIT 100 = 最新100件

    # 3. HTMLの生成
    html = "<h2>管理者用：チェックイン履歴 (最新100件)</h2>"
    html += "<table border=1 style='border-collapse: collapse; width: 80%;'>"
    html += "<tr style='background: #eee;'><th>名前</th><th>判定</th><th>時刻</th><th>緯度</th><th>経度</th></tr>"
    
    if not logs:
        html += "<tr><td colspan='5'>まだチェックインがありません</td></tr>"
    
    for row in logs:
        # 判定によって色を変える
        color = "red" if "アウト" in row['status'] else "green"
        html += f"<tr><td>{row['name']}</td>"
        html += f"<td style='color: {color}; font-weight: bold;'>{row['status']}</td>"
        html += f"<td>{row['server_time']}</td>"
        html += f"<td>{row['lat']}</td><td>{row['lon']}</td></tr>"
        
    html += "</table>"
    
    return html

if __name__ == '__main__':
    # データベース(curfew.db)とテーブルを初期化します
    # (すでに存在する場合は何も起こりません)
    init_db()
    print("--- データベースの初期化が完了しました ---")
    
    # サーバーをデバッグモードで起動
    # (debug=True にするとエラーがターミナルに表示されて便利です)
    print("--- サーバーを http://127.0.0.1:5000 で起動します ---")
    app.run(host='0.0.0.0', port=5000, debug=True)
