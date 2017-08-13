from freezegun import freeze_time
from nose.tools import *
from uvhttp.utils import start_loop, http_server
from uvoauth.uvoauth import Oauth, OauthError
from sanic import Sanic
from sanic.response import json
from urllib.parse import parse_qs
import datetime
import functools
import urllib.parse
from uvoauth.utils import *

@http_server(OauthServer)
async def test_uvoauth(server, loop):
    url = server.url.decode()

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

@http_server(OauthServer)
async def test_uvoauth_caching(server, loop):
    url = server.url.decode()

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

@http_server(OauthServer)
async def test_uvoauth_unregistered(server, loop):
    url = server.url.decode()

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
