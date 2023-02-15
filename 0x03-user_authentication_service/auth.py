#!/usr/bin/env python3
"""
This module contains the methods and attributes needed
for the authentication
"""
from bcrypt import hashpw, gensalt, checkpw
from db import DB
import uuid
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from typing import Union


def _hash_password(password: str) -> bytes:
    """
    Method that encrypts a provided password.
    Args:
        password: The password to be encrypted.
    Returns:
        bytes: The encrypted password.
    """
    return hashpw(password.encode(), gensalt())


class Auth:
    """
    Auth class to interact with the authentication database.
    Attributes:
        _db: The database object.
    """

    def __init__(self):
        """
        Constructor for the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Method that registers a user in the database.
        Args:
            email: The email of the user.
            password: The password of the user.
        Raises:
            ValueError: If the user already exists.
        Returns:
            User: The user object.
        """
        try:
            users_found = self._db.find_user_by(email=email)
            if users_found:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password).decode('utf-8')
            print(hashed_password)
            user = self._db.add_user(email, hashed_password)
            return user
