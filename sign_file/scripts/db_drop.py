import sqlalchemy
from ..db.models import Base
DATABASE_URL = 'sqlite:///./sign-file.sqlite3'

engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

Base.metadata.drop_all(engine)
