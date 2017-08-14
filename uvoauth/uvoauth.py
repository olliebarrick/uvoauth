import base64
import uvhttp.http
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class OauthError(Exception):
    pass

class Oauth(uvhttp.http.Session):
    """
    Oauth client for :mod:`uvhttp`.
    """

    def __init__(self, loop, auth_url, token_url, client_id, client_secret, redirect_url=None, conn_limit=10, resolver=None, ssl=None):
        """
        * ``loop`` is the asyncio loop to use.
        * ``auth_url`` authorization url of the oauth endpoint (e.g., https://example.com/authorize).
        * ``token_url`` token url of the oauth endpoint (e.g., https://example.com/token).
        * ``client_id`` is the oauth client id.
        * ``callback_url`` is the URL of the callback in your web application.
        """
        self.client_secret = client_secret
        self.client_id = client_id
        self.auth_url = urlparse(auth_url)
        self.auth_query = parse_qs(self.auth_url.query)
        self.redirect_url = redirect_url

        if isinstance(token_url, str):
            token_url = token_url.encode()
        self.token_url = token_url

        self.logins = {}

        self.ssl_ctx = ssl

        super().__init__(conn_limit, loop, resolver=resolver)

    def authenticate_url(self, *scopes):
        """
        Get the URL to redirect the Spotify user to. This URL should be loaded
        in the user's browser.
        """
        qs = self.auth_query.copy()
        qs['client_id'] = self.client_id
        qs['response_type'] = 'code'
        qs['redirect_uri'] = self.redirect_url
        qs['scope'] = ' '.join(scopes)
        return urlunparse(self.auth_url._replace(query=urlencode(qs)))

    def is_registered(self, identifier):
        """
        Check if an identifier is already registered.
        """
        return identifier in self.logins

    def register_auth_code(self, identifier, code):
        """
        Register the ``code`` from the oauth callback response with a unique
        identifier.
        """
        self.logins[identifier] = { "code": code }

    def get_valid_token(self, identifier):
        """
        Return a cached access token for an identifier if it is not
        expired.
        """
        if not self.is_registered(identifier):
            raise OauthError('not registered')

        if 'token' in self.logins[identifier]:
            token = self.logins[identifier]['token']
            if token['expires'] <= time.time():
                return
            return token['access_token']

    def set_token(self, identifier, token):
        """
        Set a token for an identifier.
        """
        self.logins[identifier]['refresh_token'] = token['refresh_token']
        token['expires'] = time.time() + token['expires_in']
        self.logins[identifier]['token'] = token

    async def get_token(self, identifier):
        """
        Get an authentication token for an identifier. Return an access token
        that can be used in a cookie.
        """
        token = self.get_valid_token(identifier)
        if token:
            return token

        login = self.logins[identifier]

        args = {}
        if 'refresh_token' in login:
            args['grant_type'] = 'refresh_token'
            args['refresh_token'] = login['refresh_token']
        else:
            args['grant_type'] = 'authorization_code'
            args['code'] = login['code']
            args['redirect_uri'] = self.redirect_url

        auth_token = '{}:{}'.format(self.client_id, self.client_secret)
        auth_token = base64.b64encode(auth_token.encode()).decode()

        token = await self.request(b'POST', self.token_url,
            data=urlencode(args).encode(), headers={
                b'Authorization': 'Basic {}'.format(auth_token).encode(),
                b'Content-type': b'application/x-www-form-urlencoded'
            }, ssl=self.ssl_ctx)

        self.set_token(identifier, token.json())
        return self.get_valid_token(identifier)

    async def request(self, *args, identifier=None, **kwargs):
        """
        Make a request, but add the token for the given identifier to
        the headers to authenticate the request. See :class:`uvhttp.http.Session`.
        If token is none, just make a request.
        """
        if identifier:
            if 'headers' not in kwargs:
                kwargs['headers'] = {}

            token = await self.get_token(identifier)
            kwargs['headers'][b'authorization'] = 'Bearer {}'.format(token).encode()

        return await super().request(*args, **kwargs)
