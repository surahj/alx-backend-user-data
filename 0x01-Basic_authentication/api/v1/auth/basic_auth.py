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

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the base64 encoded string
        Args:
            base64_authorization_header: base64 encoded string
        Returns:
            decoded base64 encoded string
        Raises:
            Exception: if base64_authorization_header
            is not a valid base64 encoded string
        """
        if not base64_authorization_header or \
                type(base64_authorization_header) is not str:
            return None
        try:
            encode_string = base64_authorization_header.encode("utf-8")
            decoded_str = base64.b64decode(encode_string)
            return decoded_str.decode("utf-8")
        except Exception:
            return None


    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the username and password from the decoded
        base64 encoded string
        Args:
            decoded_base64_authorization_header: decoded
            base64 encoded string
        Returns:
            user_email: user email
            user_pwd: user password
        Raises:
            ValueError: if decoded_base64_authorization_header
            is not a valid string
        """
        if not decoded_base64_authorization_header or \
                type(decoded_base64_authorization_header) is not str or \
                ":" not in decoded_base64_authorization_header:
            return None, None
        try:
            username, password = \
                decoded_base64_authorization_header.split(":", 1)
            return username, password
        except ValueError:
            return None, None
