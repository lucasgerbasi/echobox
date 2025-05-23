from flask import Flask, render_template, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import sqlite3
import os
import logging
import hashlib
import re
from datetime import datetime, timedelta
import json
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets

app = Flask(__name__)
app.secret_key = os.getenv("goonga-ginga", secrets.token_hex(32))
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

sqlite3.register_adapter(datetime, lambda val: val.isoformat(" "))
sqlite3.register_converter("timestamp", lambda val: datetime.fromisoformat(val.decode()))

Talisman(app,
         force_https=False,
         strict_transport_security=True,
         content_security_policy={
             'default-src': "'self'",
             'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
             'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
             'font-src': "'self' https://fonts.gstatic.com",
             'img-src': "'self' data:",
         }
         )

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per day", "2 per hour"],
    storage_uri="memory://"
)
limiter.init_app(app)

DB_NAME = os.getenv("DB_NAME", "echos.db")
MAX_ECHO_LENGTH = 500
MIN_ECHO_LENGTH = 3

PROFANITY_PATTERNS = [
    r'\b(spam|fake|scam|bot)\b',
    r'(https?://|www\.)',
    r'[^\w\s]{5,}',
    r'\b(fuck|shit|asshole|bitch|cunt|dick|bastard)\b'
]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('echobox.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EchoAnalytics:
    @staticmethod
    def get_stats():
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) as total FROM echos")
                total_echoes = c.fetchone()["total"]
                today = datetime.now().date()
                c.execute(
                    "SELECT COUNT(*) as today FROM echos WHERE strftime('%Y-%m-%d', created_at) = ?",
                    (today.strftime('%Y-%m-%d'),)
                )
                today_echoes = c.fetchone()["today"]
                c.execute("SELECT AVG(LENGTH(message)) as avg_length FROM echos")
                avg_length = c.fetchone()["avg_length"] or 0
                c.execute("""
                    SELECT strftime('%H', created_at) as hour, COUNT(*) as count 
                    FROM echos 
                    GROUP BY hour 
                    ORDER BY count DESC 
                    LIMIT 5
                """)
                active_hours = c.fetchall()
                return {
                    "total_echoes": total_echoes,
                    "today_echoes": today_echoes,
                    "avg_length": round(avg_length, 1),
                    "active_hours": [dict(row) for row in active_hours]
                }
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            return {"total_echoes": 0, "today_echoes": 0, "avg_length": 0, "active_hours": []}


class EchoModerator:
    @staticmethod
    def is_spam_or_inappropriate(text):
        text_lower = text.lower().strip()
        if len(text) < MIN_ECHO_LENGTH or len(text) > MAX_ECHO_LENGTH:
            return True, "Message length is invalid"
        if len(set(text_lower.split())) < len(text_lower.split()) * 0.3:
            return True, "Message appears to be spam or repetitive"
        for pattern in PROFANITY_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True, "Message contains inappropriate content"
        unique_chars = len(set(text_lower.replace(' ', '')))
        if unique_chars < 5 and len(text) > 20:
            return True, "Message appears to be invalid"
        return False, None

    @staticmethod
    def sanitize_echo(text):
        text = re.sub(r'\s+', ' ', text.strip())
        text = re.sub(r'[^\w\s\.\,\!\?\'\"\-\(\)\:\;]', '', text)
        return text


class EchoRecommender:
    @staticmethod
    def get_weighted_echo(user_echo_id, user_session_id):
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                recent_cutoff = datetime.now() - timedelta(hours=24)
                c.execute("""
                    SELECT e.id, e.message, e.created_at, e.length_category,
                           COALESCE(ev.view_count, 0) as view_count
                    FROM echos e
                    LEFT JOIN echo_views ev ON e.id = ev.echo_id
                    WHERE e.id != ? 
                    AND e.id NOT IN (
                        SELECT echo_id FROM user_echo_history 
                        WHERE session_id = ? AND viewed_at > ?
                    )
                    ORDER BY 
                        CASE 
                            WHEN ev.view_count IS NULL OR ev.view_count < 3 THEN 3
                            WHEN ev.view_count < 10 THEN 2
                            ELSE 1
                        END DESC,
                        RANDOM() 
                    LIMIT 1
                """, (user_echo_id, user_session_id, recent_cutoff))
                result = c.fetchone()
                if result:
                    EchoRecommender.record_echo_view(result["id"], user_session_id)
                    return result["message"]
                else:
                    c.execute("SELECT message FROM echos WHERE id != ? ORDER BY RANDOM() LIMIT 1", (user_echo_id,))
                    fallback = c.fetchone()
                    return fallback["message"] if fallback else None
        except Exception as e:
            logger.error(f"Recommendation error: {e}")
            return None

    @staticmethod
    def record_echo_view(echo_id, session_id):
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT OR REPLACE INTO echo_views (echo_id, view_count) 
                    VALUES (?, COALESCE((SELECT view_count FROM echo_views WHERE echo_id = ?), 0) + 1)
                """, (echo_id, echo_id))
                c.execute("""
                    INSERT INTO user_echo_history (session_id, echo_id, viewed_at) 
                    VALUES (?, ?, ?)
                """, (session_id, echo_id, datetime.now()))
                conn.commit()
        except Exception as e:
            logger.error(f"View recording error: {e}")


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS echos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_hash TEXT,
                length_category TEXT,
                is_flagged BOOLEAN DEFAULT 0,
                sentiment_score REAL DEFAULT 0.0
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS echo_views (
                echo_id INTEGER PRIMARY KEY,
                view_count INTEGER DEFAULT 0,
                FOREIGN KEY (echo_id) REFERENCES echos (id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_echo_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                echo_id INTEGER NOT NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (echo_id) REFERENCES echos (id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_echo_views_echo_id ON echo_views(echo_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_user_history_session ON user_echo_history(session_id)')
        conn.commit()
        logger.info("Database initialized.")


def get_db_connection():
    conn = sqlite3.connect(
        DB_NAME,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
    )
    conn.row_factory = sqlite3.Row
    return conn

def get_session_id():
    if 'session_id' not in session:
        session['session_id'] = secrets.token_urlsafe(32)
    return session['session_id']

def categorize_echo_length(length):
    if length < 50:
        return "short"
    elif length < 200:
        return "medium"
    else:
        return "long"

def log_analytics_event(event_type, event_data=None):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO analytics_events (event_type, event_data, session_id) 
                VALUES (?, ?, ?)
            """, (event_type, json.dumps(event_data) if event_data else None, get_session_id()))
            conn.commit()
    except Exception as e:
        logger.error(f"Analytics logging error: {e}")

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def index():
    session_id = get_session_id()
    if request.method == "POST":
        user_echo = request.form.get("echo", "").strip()
        is_inappropriate, error_msg = EchoModerator.is_spam_or_inappropriate(user_echo)
        if is_inappropriate:
            log_analytics_event("echo_rejected", {"reason": error_msg, "length": len(user_echo)})
            return render_template("index.html",
                                   received_echo="Echo rejected: " + error_msg,
                                   stats=EchoAnalytics.get_stats())
        user_echo = EchoModerator.sanitize_echo(user_echo)
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                session_hash = hashlib.sha256((session_id + user_echo).encode()).hexdigest()
                length_category = categorize_echo_length(len(user_echo))
                c.execute("""
                    SELECT id FROM echos 
                    WHERE session_hash = ? AND created_at > datetime('now', '-1 hour')
                """, (session_hash,))
                if c.fetchone():
                    log_analytics_event("duplicate_echo_attempt")
                    return render_template("index.html",
                                           received_echo="You've shared this echo recently. Try something new!",
                                           stats=EchoAnalytics.get_stats())
                c.execute("""
                    INSERT INTO echos (message, session_hash, length_category) 
                    VALUES (?, ?, ?)
                """, (user_echo, session_hash, length_category))
                last_id = c.lastrowid
                conn.commit()
                logger.info(f"Echo saved with ID: {last_id} from session: {session_id[:8]}...")
                received_echo = EchoRecommender.get_weighted_echo(last_id, session_id)
                if not received_echo:
                    received_echo = "Your voice echoes in the void... You're among the first to share here."
                log_analytics_event("echo_exchange", {
                    "echo_length": len(user_echo),
                    "category": length_category
                })
        except Exception as e:
            logger.error(f"Database error: {e}")
            return render_template("500.html"), 500
        return render_template("index.html",
                               received_echo=received_echo,
                               stats=EchoAnalytics.get_stats())
    log_analytics_event("page_view")
    return render_template("index.html", stats=EchoAnalytics.get_stats())

@app.route("/api/stats")
@limiter.limit("30 per minute")
def api_stats():
    return jsonify(EchoAnalytics.get_stats())

@app.route("/api/health")
def health_check():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT 1")
            return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route("/analytics")
@limiter.limit("5 per minute")
def analytics_dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM echos 
                WHERE created_at > datetime('now', '-7 days')
                GROUP BY DATE(created_at) 
                ORDER BY date DESC
            """)
            daily_activity = [dict(row) for row in c.fetchall()]
            c.execute("""
                SELECT length_category, COUNT(*) as count 
                FROM echos 
                GROUP BY length_category
            """)
            length_distribution = [dict(row) for row in c.fetchall()]
            c.execute("""
                SELECT SUBSTR(e.message, 1, 50) || '...' as preview, ev.view_count
                FROM echos e
                JOIN echo_views ev ON e.id = ev.echo_id
                WHERE ev.view_count > 5
                ORDER BY ev.view_count DESC
                LIMIT 10
            """)
            popular_echoes = [dict(row) for row in c.fetchall()]
            analytics_data = {
                "daily_activity": daily_activity,
                "length_distribution": length_distribution,
                "popular_echoes": popular_echoes,
                "stats": EchoAnalytics.get_stats()
            }
            return jsonify(analytics_data)
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({"error": "Analytics unavailable"}), 500

@app.route("/about")
def about():
    return render_template("about.html", stats=EchoAnalytics.get_stats())

@app.errorhandler(404)
def not_found(e):
    log_analytics_event("404_error", {"path": request.path})
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    log_analytics_event("500_error", {"error": str(e)})
    return render_template("500.html"), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    log_analytics_event("rate_limit_hit", {"limit": str(e.description)})
    return render_template("rate_limit.html"), 429

@app.context_processor
def inject_global_vars():
    return {
        'current_year': datetime.now().year,
        'app_version': '2.0.0'
    }

def cleanup_old_data():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                DELETE FROM user_echo_history 
                WHERE viewed_at < datetime('now', '-30 days')
            """)
            c.execute("""
                DELETE FROM analytics_events 
                WHERE created_at < datetime('now', '-90 days')
            """)
            conn.commit()
            logger.info("Old data cleaned up successfully")
    except Exception as e:
        logger.error(f"Cleanup error: {e}")

@app.cli.command()
def init_database():
    init_db()
    print("Database initialized successfully!")

@app.cli.command()
def cleanup_data():
    cleanup_old_data()
    print("Data cleanup completed!")

@app.cli.command()
def show_stats():
    stats = EchoAnalytics.get_stats()
    print(f"Today's Echoes: {stats['today_echoes']}")
    print(f"Average Length: {stats['avg_length']} characters")

if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    init_db()
    if not app.debug:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler('echobox.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('EchoBox startup')