# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystoneclient.auth.identity import v3
from oslo.config import cfg

class X509Method(v3.AuthMethod):

    _method_parameters = ['client_cert']

    def __init__(self, **kwargs):
        """Construct a X509 based authentication method.
        """
        super(X509Method, self).__init__(**kwargs)


    def get_auth_data(self, session, auth, headers, request_kwargs=None,
                      **kwargs):

        request_kwargs['cert'] = self.client_cert
        return 'external', {}


class X509(v3.AuthConstructor):
    _auth_method_class = X509Method

    @classmethod
    def get_options(cls):
        options = super(X509, cls).get_options()

        options.extend([
            cfg.StrOpt('client-cert', help='Client certificate'),
        ])

        return options
