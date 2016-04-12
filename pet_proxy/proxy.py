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

import sys

from oslo_config import cfg
from oslo_log import log

from pet_proxy import notifier
from pet_proxy import snmp


def _run_proxy():
    log.register_options(cfg.CONF)
    log.set_defaults(default_log_levels=['amqp=WARNING',
                                         'amqplib=WARNING',
                                         'qpid.messaging=INFO',
                                         'oslo_messaging=INFO',
                                         ])
    cfg.CONF(sys.argv[1:], project='pet-proxy')
    notifier.init(cfg.CONF)
    log.setup(cfg.CONF, 'pet-proxy')
    snmp.run_dispatcher(cfg.CONF)


def main():
    _run_proxy()


if __name__ == '__main__':
    sys.exit(main())
