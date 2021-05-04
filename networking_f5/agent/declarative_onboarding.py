# Copyright 2018, 2019 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools

import requests
from oslo_log import log as logging
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse
from tenacity import retry, stop_after_attempt, \
    wait_incrementing, retry_if_exception_type

from networking_f5.agent.f5_agent import F5Backend

LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5

DO_LOGIN_PATH = '/mgmt/shared/authn/login'
DO_TOKENS_PATH = '/mgmt/shared/authz/tokens/{}'
DO_PATH = '/mgmt/shared/declarative-onboarding'

SCHEMA = {
    'schemaVersion': '1.8.0',
    'class': 'Device',
    'async': False,
    'label': 'networking-f5-agent',
    'Common': {
        'class': 'Tenant',
    }
}

VLAN = {
    'class': 'VLAN',
    'tag': 0,
    'interfaces': [],
}

SELFIP = {
    'class': 'SelfIp',
    'vlan': None,
    'address': None,
}


class F5DeclarativeOnboardingBackend(F5Backend):
    def __init__(self, cfg, uri):
        super(F5DeclarativeOnboardingBackend, self).__init__()
        self.conf = cfg
        self.do_client = F5DoClient(
            bigip_url=uri,
            enable_verify=self.conf.F5.https_verify,
        )

    def sync_all(self, vlans, selfips):
        do = SCHEMA.copy()

        if self.conf.F5.mgmt_tag:
            self._construct_mgmt(do)

        self._construct_vlans(do, vlans)
        self._construct_selfips(do, selfips)
        self.do_client.post(json=do)

    def _construct_mgmt(self, do):
        do['Common']['cc-mgmt'] = VLAN.copy()
        do['Common']['cc-mgmt']['mtu'] = self.conf.F5.mgmt_mtu
        do['Common']['cc-mgmt']['tag'] = self.conf.F5.mgmt_tag

        do['Common']['cc-mgmt0'] = SELFIP.copy()
        do['Common']['cc-mgmt0']['vlan'] = 'cc-mgmt'
        do['Common']['cc-mgmt0']['trafficGroup'] = \
            self.conf.F5.mgmt_trafficgroup
        do['Common']['cc-mgmt0']['address'] = self.conf.F5.mgmt_address

    @staticmethod
    def _construct_vlans(do, vlans):
        for vlan, val in list(vlans.items()):
            do['Common'][vlan] = VLAN.copy()
            do['Common'][vlan]['tag'] = val['tag']
            do['Common'][vlan]['mtu'] = val['mtu']

    @staticmethod
    def _construct_selfips(do, selfips):
        for selfip, val in list(selfips.items()):
            do['Common'][selfip] = SELFIP.copy()
            do['Common'][selfip]['address'] = val['ip_address']
            do['Common'][selfip]['vlan'] = val['vlan']


class F5DoClient(object):
    def __init__(self, bigip_url, enable_verify=True, enable_token=True):
        self.bigip = parse.urlsplit(bigip_url, allow_fragments=False)
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.token = None
        self.s = self._create_session()

    def _url(self, path):
        return parse.urlunsplit(
            parse.SplitResult(scheme=self.bigip.scheme,
                              netloc=self.bigip.hostname,
                              path=path,
                              query='',
                              fragment='')
        )

    def _create_session(self):
        session = requests.Session()
        session.verify = self.enable_verify
        return session

    def authorized(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except requests.HTTPError as e:
                if e.response.status_code == 401:
                    self.reauthorize()
                    return func(self, *args, **kwargs)
                else:
                    raise e
        return wrapper

    @retry(
        retry=retry_if_exception_type(requests.HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS),
    )
    def reauthorize(self):
        # Login
        credentials = {
            "username": self.bigip.username,
            "password": self.bigip.password,
            "loginProviderName": "tmos"
        }
        basicauth = HTTPBasicAuth(self.bigip.username, self.bigip.password)
        r = self.s.post(self._url(DO_LOGIN_PATH),
                        json=credentials, auth=basicauth)
        r.raise_for_status()
        self.token = r.json()['token']['token']

        self.s.headers.update({'X-F5-Auth-Token': self.token})

        patch_timeout = {
            "timeout": "36000"
        }
        r = self.s.patch(
            self._url(
                DO_TOKENS_PATH.format(
                    self.token)),
            json=patch_timeout)
        LOG.debug("Reauthorized!")

    @retry(
        retry=retry_if_exception_type(requests.HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @authorized
    def post(self, **kwargs):
        LOG.debug("Calling POST with JSON %s", kwargs.get('json'))
        response = self.s.post(self._url(DO_PATH), **kwargs)
        response.raise_for_status()
        LOG.debug(
            "POST finished with %d: %s",
            response.status_code,
            response.text)
        return response

    @retry(
        retry=retry_if_exception_type(requests.HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @authorized
    def get(self):
        response = self.s.get(self._url(DO_PATH))
        response.raise_for_status()
        LOG.debug(
            "GET finished with %d: %s",
            response.status_code,
            response.text)
        return response
