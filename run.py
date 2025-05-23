import os
from app import app, init_db

if __name__ == '__main__':
    init_db()
    config_name = os.getenv('FLASK_CONFIG', 'development')
    debug_mode = config_name == 'development'
    port = int(os.getenv('PORT', 5000))
    print(f"Starting EchoBox server in {config_name} mode...")
    print(f"Server will be available at http://localhost:{port}")
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=port
    )