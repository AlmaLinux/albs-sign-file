from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
import databases


Base = declarative_base()


class Users(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True)
    email = Column(String)
    password = Column(String)
