# Secure Portfolio Site 🔐

A personal portfolio built with Flask that showcases my projects, experience, and resume—while also demonstrating secure full-stack web development practices aligned with the OWASP Top 10.

---

## 🚀 Features

- 🔐 Secure user authentication with hashed passwords
- 🧪 Defense against SQL Injection, XSS, and CSRF
- 👤 Role-based access control (admin vs public)
- 📝 Admin dashboard for content updates
- 📄 Public project gallery & contact form
- 📦 Deployed with environment-based secrets and logging

---

## 🔧 Tech Stack

- **Backend:** Flask, SQLAlchemy, Flask-Login, Flask-WTF
- **Database:** SQLite (dev), PostgreSQL (planned for prod)
- **Frontend:** HTML5, CSS3 (Tailwind/Bootstrap optional)
- **Security:** bcrypt, CSRF tokens, environment variables
- **Dev Tools:** PyCharm, GitHub, Docker (planned), GitHub Actions (CI/CD soon)

---

## ⚙️ Setup Instructions

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/secure-portfolio-site.git
cd secure-portfolio-site

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Then update .env with your own SECRET_KEY

# Run the app
python run.py
