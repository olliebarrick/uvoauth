from nose.tools import *
from uvhttp.utils import HttpServer
from sanic.response import json
from urllib.parse import parse_qs

FIRST_TOKEN = 'first token'
SECOND_TOKEN = 'second token'
FIRST_REFRESH_TOKEN = 'refresh token'
SECOND_REFRESH_TOKEN = 'refresh token 2'
ACCESS_CODE = 'access code'

class OauthServer(HttpServer):
    def add_routes(self):
        super().add_routes()

        self.app.add_route(self.token, '/token', methods=['POST'])
        self.app.add_route(self.api, '/api')

    async def token(self, request):
        assert_equal(request.headers['Authorization'], 'Basic MTIzNDo1Njc4')
        data = parse_qs(request.body.decode())

        token = {
            "access_token": FIRST_TOKEN,
            "token_type": "Bearer",
            "scope": 'scope1 scope2',
            "expires_in": 30,
            "refresh_token": FIRST_REFRESH_TOKEN
        }

        if 'code' in data:
            assert_equal(data['grant_type'][0], 'authorization_code')
            assert_equal(data['code'][0], ACCESS_CODE)
            assert_equal(data['redirect_uri'][0], 'http://example.com/callback')
        elif 'refresh_token' in data:
            assert_equal(data['grant_type'][0], 'refresh_token')

            if data['refresh_token'][0] == FIRST_REFRESH_TOKEN:
                token['access_token'] = SECOND_TOKEN
                token['refresh_token'] = SECOND_REFRESH_TOKEN
            else:
                assert_equal(data['refresh_token'][0], SECOND_REFRESH_TOKEN)
        else:
            raise AssertionError('No code or refresh token!')

        return json(token)

    async def api(self, request):
        assert_in(request.headers['Authorization'], [ 'Bearer ' + FIRST_TOKEN, 'Bearer ' + SECOND_TOKEN ])
        return json({'Authorization': request.headers['Authorization']})

