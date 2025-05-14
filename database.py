from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_db():
    from models import User, Contact, Message
    db.create_all()
