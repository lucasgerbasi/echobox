
# EchoBox

EchoBox is a simple Flask-based anonymous confession and echo system where users can submit messages and receive random ones from others.

<div align="center">
  <img src="https://github.com/user-attachments/assets/fc543610-e7e1-4d74-8827-74c6eeeaf732" alt="EchoBox screenshot" />
</div>

## Features

- Configurable settings via environment variables.
- Profanity filtering.
- Separate configurations for development, production, and testing.
- SQLite database by default with option to configure database URL.

## Tech Stack

### Backend
- **Python**
- **Flask** – Web framework
- **Werkzeug** – Session + security middleware

### Frontend
- **HTML5** – Page structure
- **CSS3** – Custom styling
- **Jinja2** – Templating engine
- **JavaScript** – Light usage (if applicable)
- **Google Fonts** – Included via CSP headers

### Database
- **SQLite** – For storing echoes, views, sessions, and analytics

## Setup

1. **Clone the repository**

```bash
git clone https://github.com/lucasgerbasi/echobox.git
cd echobox
````

2. **Create a virtual environment and install dependencies**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Configure environment variables**

Create a `.env` file in the root directory with content like:

```
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///echobox.db
FLASK_CONFIG=development
PORT=5000
```

Replace `your-secret-key` with a secure random string for production.

4. **Run the application**

```bash
python run.py
```

By default, the app runs in development mode on `http://localhost:5000`.

## Important Notes

* **Never use the default secret key in production.** Always set `SECRET_KEY` in your environment variables.
* The default database is SQLite for ease of development. You can change this by setting `DATABASE_URL`.
* Profanity filtering is enabled by default but can be toggled in the configuration.

## License

This project is licensed under the MIT License.
