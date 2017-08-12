from nose.tools import *
from uvhttp.utils import start_loop
from uvoauth.uvoauth import Oauth
from sanic import Sanic
from sanic.response import json
from urllib.parse import parse_qs
import functools
import urllib.parse

def oauth_server(func):
    @functools.wraps(func)
    @start_loop
    async def oauth_wrapper(loop, *args, **kwargs):
        app = Sanic(__name__)
        app.config.LOGO = None

        @app.route('/token', methods=['POST'])
        async def token(request):
            assert_equal(request.headers['Authorization'], 'Basic MTIzNDo1Njc4')
            data = parse_qs(request.body.decode())

            if 'code' in data:
                assert_equal(data['grant_type'][0], 'access_code')
                assert_equal(data['code'][0], 'abcdefgh')
                assert_equal(data['redirect_uri'][0], 'http://example.com/callback')
            elif 'refresh_token' in data:
                assert_equal(data['grant_type'][0], 'refresh_token')
                assert_equal(data['refresh_token'][0], 'hello')
            else:
                raise AssertionError('No code or refresh token!')

            return json({
                "access_token": "aosentuh",
                "token_type": "Bearer",
                "scope": 'scope1 scope2',
                "expires_in": 30,
                "refresh_token": "hello"
            })

        @app.route('/api')
        async def api(request):
            assert_equal(request.headers['Authorization'], 'Bearer aosentuh')
            return json({})

        server = await app.create_server(host='127.0.0.1', port=8089)

        try:
            await func(app, loop, *args, **kwargs)
        finally:
            server.close()

    return oauth_wrapper

@oauth_server
async def test_uvoauth(app, loop):
    url = 'http://127.0.0.1:8089/'

    oauth = Oauth(loop, url + 'authorize', url + 'token', '1234', '5678',
            'http://example.com/callback')

    auth_url = oauth.authenticate_url('scope1', 'scope2')
    auth_url = urllib.parse.urlsplit(auth_url)
    qs = urllib.parse.parse_qs(auth_url.query)

    assert_equal(qs['client_id'][0], '1234')
    assert_equal(qs['response_type'][0], 'code')
    assert_equal(qs['redirect_uri'][0], 'http://example.com/callback')
    assert_equal(qs['scope'][0], 'scope1 scope2')

    assert_equal(oauth.is_registered('newuser'), False)

    oauth.register_auth_code('newuser', 'abcdefgh')

    assert_equal(oauth.is_registered('newuser'), True)

    assert_equal(await oauth.get_token('newuser'), 'aosentuh')

    response = await oauth.request(b'GET', (url + 'api').encode(), identifier='newuser')
    assert_equal(response.json(), {})
