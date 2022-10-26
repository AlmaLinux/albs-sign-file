"""
This module responsible for JWT token generation/verification
"""
from datetime import datetime, timedelta
import jwt
from sign.api.schema import Token, UserSchema
from sign.db.models import User


class JWT:
    def __init__(self, secret: str, expire_minutes: int,
                 hash_algoritm: str):
        self.secret = secret
        self.expire_minutes = expire_minutes
        self.hash_algoritm = hash_algoritm

    def encode(self, user_id: int, email: str) -> Token:
        exp = datetime.now() + timedelta(minutes=self.expire_minutes)
        exp_timestamp = int(exp.timestamp())
        encoded_token = jwt.encode(
            {'user_id': user_id, 'email': email, 'exp': exp_timestamp},
            key=self.secret, algorithm=self.hash_algoritm)
        return Token(token=encoded_token,
                     user_id=user_id,
                     exp=exp_timestamp)

    def decode(self, token: str) -> UserSchema:
        decoded_token = jwt.decode(token, self.secret, algorithms=[
            self.hash_algoritm, ])
        return UserSchema(user_id=decoded_token['user_id'],
                          email=decoded_token['email'])
