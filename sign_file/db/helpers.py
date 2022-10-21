import sqlalchemy
from .models import Base


DATABASE_URL = 'sqlite:///./sign-file.sqlite'

engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)


def db_create():
    Base.metadata.create_all(engine)


def db_drop():
    Base.metadata.drop_all(engine)
