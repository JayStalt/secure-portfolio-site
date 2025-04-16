# 🔐 Secure Portfolio Website

A secure full-stack portfolio application built with Flask, featuring user authentication, admin-only project management, and real-time security logging. Designed to showcase your work and cybersecurity skills in one clean platform.

[🌐 View Live Demo]([[https://your-live-url.onrender.com](https://secure-portfolio-site.onrender.com))

---

## 🚀 Features

- ✅ User authentication (Login, Logout, Register)
- 🔐 Role-based access control (`admin@example.com`)
- 🧱 Admin dashboard with project CRUD (create/edit/delete)
- 📂 Public project portfolio page
- 📋 Real-time security logging (viewable in admin panel)
- ☁️ Deployed using [Render](https://render.com)
- 🌱 Environment configuration via `.env`

---

## 🧰 Tech Stack

- **Backend:** Flask, Flask-Login, SQLAlchemy
- **Frontend:** Jinja2 Templates, HTML/CSS
- **Database:** SQLite (via SQLAlchemy ORM)
- **Deployment:** Gunicorn + Render
- **Security Tools:** bcrypt, Flask-WTF, custom logging

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
