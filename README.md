# 🔐 Secure Portfolio Website

A secure full-stack portfolio application built with Flask, featuring user authentication, admin-only project management, and real-time security logging. Designed to showcase your work and cybersecurity skills in one clean platform.

[🌐 View Live Demo](https://secure-portfolio-site.onrender.com)

---

## 🚀 Features

- ✅ User authentication (Login, Logout, Register)
- 🔐 Role-based access control (`admin@example.com`)
- 🧱 Admin dashboard with project CRUD (create/edit/delete)
- 📂 Public project portfolio with tabbed categories:
  - Cybersecurity
  - Full Stack Development
  - Games
  - Creative Writing
- 📊 Security Metrics dashboard with custom log viewer
- 🛡 Built-in cyber microtools:
  - Header Analyzer
  - JWT Decoder
  - Threat Simulation
- 📋 Real-time security logging (successful/failed login, project edits, etc.)
- ☁️ Deployed using [Render](https://render.com)
- 🌱 Environment configuration via `.env`

---

## 🧰 Tech Stack

- **Backend:** Flask, Flask-Login, SQLAlchemy
- **Frontend:** Jinja2 Templates, HTML/CSS
- **Database:** SQLite (via SQLAlchemy ORM)
- **Deployment:** Gunicorn + Render
- **Security Tools:** bcrypt, Flask-WTF, request logging, session management

---

## 📸 Screenshots

> _(To be added later)_

---

## 🛠 Local Setup

```bash
git clone https://github.com/JayStalt/secure-portfolio-site
cd secure-portfolio-site
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

