from nose.tools import *
from uvhttp.utils import start_loop
from uvoauth.uvoauth import Oauth
from sanic import Sanic
from sanic.response import json
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

            if 'code' in request.form:
                assert_equal(request.form['grant_type'], 'access_code')
                assert_equal(request.form['code'], 'abcdefgh')
                assert_equal(request.form['redirect_uri'], 'http://example.com/callback')
            elif 'refresh_token' in request.form:
                assert_equal(request.form['grant_type'], 'refresh_token')
                assert_equal(request.form['refresh_token'], 'hello')
            else:
                raise AssertionError('No code or refresh token!')

            return json({
                "access_token": "aosentuh",
                "token_type": "Bearer",
                "scope": request.form['scope'],
                "expires_in": 30,
                "refresh_token": "hello"
            })

        @app.route('/api')
        async def api(request):
            pass

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

    assert_equal(await oauth.get_token('newuser'), 'hello')

    response = await oauth.request('newuser', b'GET', url + 'api')
    assert_equal(response.json(), {'authorization': 'Bearer hello'})
