import logging

from certbot_dns_digitalocean._internal.dns_digitalocean import _DigitalOceanClient

from middlewared.schema import accepts, Dict, Str, ValidationErrors

from .base import Authenticator


logger = logging.getLogger(__name__)


class DigitalOceanAuthenticator(Authenticator):

    NAME = 'digitalocean'
    SCHEMA = Dict(
        'digitalocean',
        Str('api_token', empty=False, null=True, title='API Token'),
    )

    def initialize_credentials(self):
        self.api_token = self.attributes.get('api_token')

    @accepts(SCHEMA)
    def validate_credentials(data):
        verrors = ValidationErrors()
        if not data.get('api_token'):
            verrors.add('api_key', 'Attribute is required when using a Global API Key.')
        verrors.check()

    def _perform(self, domain, validation_name, validation_content):
        self.get_digitalocean_object().add_txt_record(domain, validation_name, validation_content)

    def get_digitalocean_object(self):
        return _DigitalOceanClient(self.api_token)

    def _cleanup(self, domain, validation_name, validation_content):
        self.get_digitalocean_object().del_txt_record(domain, validation_name, validation_content)
