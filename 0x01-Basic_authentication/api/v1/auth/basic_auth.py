#!/usr/bin/env python3
"""
Basic Authentication inheriting from the Auth class
"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """
    Contains implementation of authentication methods and
    inherits from Auth class
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the base64 encoded string from the
        authorization header
        Args:
            authorization_header: authorization header
        Returns:
            base64 encoded string
        Raises:
            ValueError: if authorization_header
            is not a valid string
        """
        if not authorization_header or \
                type(authorization_header) is not str or \
                authorization_header.split()[0].lower() != "basic":
            return None
        return authorization_header.split(" ")[1]
