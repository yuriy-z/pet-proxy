# Copyright 2016 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log
import requests

from pet_proxy import exception

LOG = log.getLogger(__name__)
CONF = cfg.CONF

ironic_opts = [
    cfg.StrOpt('api_url',
               help='URL of Ironic API service')
]

CONF.register_opts(ironic_opts)


#TODO: use client
def get_source(platform_uuid):
	url = '%(api)s/alert_sources/%(uuid)s' % {'api': CONF.api_url.rstrip('/'),
	                                          'uuid': platform_uuid}

	def _handle_error(reason):
		message = 'Ironic API error: %s' % reason
		LOG.error(message)
		raise exception.IronicAPIException(message)

	try:
		resp = requests.get(url, headers = {'Accept': 'application/json'})
	except Exception as e:
		_handle_error(e)

	if resp.status_code != 200:
		_handle_error(resp.text)

	result = resp.json()
	return result['source_uuid'], result['source_type']
