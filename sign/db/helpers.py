from requests import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sign.auth.hash import get_hash
from sign.db.models import Base, User
from sign.errors import UserNotFoudError
from sign.config import settings


engine = create_engine(
    settings.db_url, connect_args={"check_same_thread": False}
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
    hashed = get_hash(password)
    u = User(email=email, password=hashed)
    s = get_session()
    s.add(u)
    s.commit()
    u_id = u.id
    s.close()
    return u_id


def get_user(email: str) -> User:
    session = get_session()
    user = session.query(User).\
        filter(User.email == email).first()
    if not user:
        raise UserNotFoudError
    return user


def update_password(email: str, password: str):
    hashed = get_hash(password)
    session = get_session()
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
