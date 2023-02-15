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
