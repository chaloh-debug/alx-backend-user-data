#!/usr/bin/env python3
""" Basic authentication module """
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User

class BasicAuth(Auth):
    """ """
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """ returns the Base64 part of the Authorization header """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            mtch = re.fullmatch(pattern, authorization_header.strip())
            if mtch is not None:
                return mtch.group('token')
        return None
    
    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """ Decodes the base64-encoded authorization header. """
        if type(base64_authorization_header) == str:
            try:
                result = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return result.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
            
    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """ """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            mtch = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if mtch is not None:
                user_email = mtch.group('user')
                password = mtch.group('password')
                return user_email, password
            return None, None
        

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                res = User.search({'email': user_email})
            except Exception:
                return None
            if len(res) < 1:
                return None
            if res[0].is_valid_password(user_pwd):
                return res[0]
        return None
        

    def current_user(self, request=None) -> TypeVar('User'):
        """ """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)