from freezegun import freeze_time
from nose.tools import *
from uvhttp.utils import start_loop
from uvoauth.uvoauth import Oauth, OauthError
from sanic import Sanic
from sanic.response import json
from urllib.parse import parse_qs
import datetime
import functools
import urllib.parse

FIRST_TOKEN = 'first token'
SECOND_TOKEN = 'second token'
FIRST_REFRESH_TOKEN = 'refresh token'
SECOND_REFRESH_TOKEN = 'refresh token 2'
ACCESS_CODE = 'access code'

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

            token = {
                "access_token": FIRST_TOKEN,
                "token_type": "Bearer",
                "scope": 'scope1 scope2',
                "expires_in": 30,
                "refresh_token": FIRST_REFRESH_TOKEN
            }

            if 'code' in data:
                assert_equal(data['grant_type'][0], 'access_code')
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

        @app.route('/api')
        async def api(request):
            assert_in(request.headers['Authorization'], [ 'Bearer ' + FIRST_TOKEN, 'Bearer ' + SECOND_TOKEN ])
            return json({'Authorization': request.headers['Authorization']})

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

    oauth.register_auth_code('newuser', ACCESS_CODE)

    assert_equal(oauth.is_registered('newuser'), True)

    assert_equal(await oauth.get_token('newuser'), FIRST_TOKEN)

    response = await oauth.request(b'GET', (url + 'api').encode(), identifier='newuser')
    assert_equal(response.json(), {'Authorization': 'Bearer {}'.format(FIRST_TOKEN)})

@oauth_server
async def test_uvoauth_caching(app, loop):
    url = 'http://127.0.0.1:8089/'

    oauth = Oauth(loop, url + 'authorize', url + 'token', '1234', '5678',
            'http://example.com/callback')

    oauth.register_auth_code('newuser', ACCESS_CODE)

    api_url = (url + 'api').encode()

    now = datetime.datetime.now()
    with freeze_time(now) as frozen:
        response = await oauth.get(api_url, identifier='newuser')
        assert_equal(response.json(), {'Authorization': 'Bearer {}'.format(FIRST_TOKEN)})

        frozen.tick(delta=datetime.timedelta(seconds=29))
        response = await oauth.get(api_url, identifier='newuser')
        assert_equal(response.json(), {'Authorization': 'Bearer {}'.format(FIRST_TOKEN)})

        # The token expires at 30 seconds
        frozen.tick(delta=datetime.timedelta(seconds=1))
        response = await oauth.get(api_url, identifier='newuser')
        assert_equal(response.json(), {'Authorization': 'Bearer {}'.format(SECOND_TOKEN)})

        # It should expire again after 30 seconds.
        frozen.tick(delta=datetime.timedelta(seconds=30))
        response = await oauth.get(api_url, identifier='newuser')
        assert_equal(response.json(), {'Authorization': 'Bearer {}'.format(FIRST_TOKEN)})

@oauth_server
async def test_uvoauth_unregistered(app, loop):
    url = 'http://127.0.0.1:8089/'

    oauth = Oauth(loop, url + 'authorize', url + 'token', '1234', '5678',
            'http://example.com/callback')

    assert_raises(OauthError, oauth.get_valid_token, 'newuser')

    try:
        await oauth.get_token('newuser')
    except OauthError:
        pass
    else:
        raise AssertionError('Should have raised OauthError.')

    try:
        await oauth.request(b'GET', (url + 'api').encode(), identifier='newuser')
    except OauthError:
        pass
    else:
        raise AssertionError('Should have raised OauthError.')
