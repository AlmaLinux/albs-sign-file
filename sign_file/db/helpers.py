from requests import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import bcrypt
from .models import Base, User
from errors import UserNotFoudError

DATABASE_URL = 'sqlite:///./sign-file.sqlite3'

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)


def get_session() -> Session:
    Session = sessionmaker()
    Session.configure(bind=engine)
    s = Session()
    return s


def db_create():
    Base.metadata.create_all(engine)


def db_drop():
    Base.metadata.drop_all(engine)


def create_user(email: str, password: str):
    hashed = bcrypt.hashpw(str.encode(password),
                           bcrypt.gensalt())
    u = User(email=email, password=hashed)
    s = get_session()
    s.add(u)
    s.commit()
    u_id = u.id
    s.close()
    return u_id


def update_password(email: str, password: str):
    hashed = bcrypt.hashpw(str.encode(password),
                           bcrypt.gensalt())
    session = get_session()
    session.delete
    row_count = session.query(User).\
        filter(User.email == email).\
        update({'password': hashed})
    if row_count == 0:
        raise UserNotFoudError
    session.commit()
    session.close()


def delete_user(email: str):
    session = get_session()
    row_count = session.query(User).\
        filter(User.email == email).\
        delete()
    if row_count == 0:
        raise UserNotFoudError
    session.commit()
    session.close()
