from enum import unique
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
import databases


Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
