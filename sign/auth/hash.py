"""
Module for bcrypt hash generation and verification
"""
import bcrypt


def get_hash(in_str: str) -> str:
    return bcrypt.hashpw(str.encode(in_str),
                         bcrypt.gensalt()).decode('utf-8')


def hash_valid(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(str.encode(password), str.encode(hashed_password))
