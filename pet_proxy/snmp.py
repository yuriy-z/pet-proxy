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

import datetime
import uuid

from oslo_config import cfg
from oslo_context import context
from oslo_log import log
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1 import error
from pyasn1.codec.ber import decoder
from pysnmp.proto import api

from pet_proxy import exception
from pet_proxy import ironic
from pet_proxy import notifier
from pet_proxy import pet

LOG = log.getLogger(__name__)

snmp_opts = [
    cfg.ListOpt('alerts_interfaces',
                help='List interfaces "address:port" for listening, default '
                     'port is 162')
]

CONF = cfg.CONF
CONF.register_opts(snmp_opts)

# iso(1).org(3).dod(6).internet(1).private(4).enterprises(1)
# .wired_for_management(3183).PET(1).version(1)
_PET_ENTERPRISE_OID = (1, 3, 6, 1, 4, 1, 3183, 1, 1)
_PET_BINDING_OID = (1, 3, 6, 1, 4, 1, 3183, 1, 1, 1)


def _send_notification(trap, bindings):
    platform_uuid = bindings['system_guid']
    # TODO: cache results
    try:
        source_uuid, source_type = ironic.get_source(platform_uuid)
    except exception.IronicAPIException as e:
        LOG.error('Skipping alert from %(uuid)s, error: %(error)s',
                  {'uuid': platform_uuid, 'error': e})
        return

    rpc_notifier = notifier.get_notifier()

    message = {'message_id': str(uuid.uuid4()),
               'timestamp': datetime.datetime.utcnow(),
               'event_type': 'hardware.ipmi.alert'}
    uuid_type = source_type + '_uuid'
    message[uuid_type] = source_uuid

    payload = {}
    payload.update(trap)
    payload.update(bindings)
    LOG.debug('Payload is %s', payload)
    message['payload'] = payload

    ctx = context.get_admin_context()
    try:
        rpc_notifier.info(ctx, 'hardware.ipmi.alert', message)
    except Exception as e:
        LOG.error('Can not send alert from %(uuid)s, error: %(error)s',
                  {'uuid': platform_uuid, 'error': e})


def callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    while wholeMsg:
        LOG.debug('Notification message from %(domain)s:%(address)s: ',
                  {'domain': transportDomain, 'address': transportAddress})

        msgVer = int(api.decodeMessageVersion(wholeMsg))
        if msgVer in api.protoModules:
            pMod = api.protoModules[msgVer]
        else:
            LOG.warning('Unsupported SNMP version %(version)s in message from '
                        '%(domain)s:%(address)s',
                        {'version': msgVer, 'domain': transportDomain,
                         'address': transportAddress})
            return
        reqMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message())
        reqPDU = pMod.apiMessage.getPDU(reqMsg)
        if reqPDU.isSameTypeWith(pMod.TrapPDU()):
            if msgVer == api.protoVersion1:
                enterprise = pMod.apiTrapPDU.getEnterprise(reqPDU)
                if enterprise.asTuple() != _PET_ENTERPRISE_OID:
                    LOG.warning('Not a PET trap in message from '
                                '%(domain)s:%(address)s',
                                {'domain': transportDomain,
                                 'address': transportAddress})
                    return

                agent_addr = pMod.apiTrapPDU.getAgentAddr(reqPDU).prettyPrint()
                LOG.debug('Agent address is %s', agent_addr)

                specific_trap = int(pMod.apiTrapPDU.getSpecificTrap(reqPDU))

                varBinds = pMod.apiTrapPDU.getVarBindList(reqPDU)
                oct_values = None
                for oid, val in varBinds:
                    if oid == _PET_BINDING_OID:
                        try:
                            oct_values = val['simple']['string'].asOctets()
                        except error.PyAsn1Error:
                            pass

                if oct_values is None:
                    LOG.error('Invalid trap variables in message from '
                              '%(domain)s:%(address)s',
                              {'domain': transportDomain,
                               'address': transportAddress})
                    return

                try:
                    parsed_trap = pet.parse_specific_trap(specific_trap)
                    bindings = pet.parse_pet_values(oct_values)
                except exception.PETProxyException as e:
                    LOG.error('Error in message from %(domain)s:%(address)s: '
                              '%(error)s',
                              {'domain': transportDomain,
                               'address': transportAddress,
                               'error': e})
                    return

                _send_notification(parsed_trap, bindings)

            else:
                # not supported by PET spec
                LOG.warning('Only SNMP version 1 is supported by PET, '
                            '%(version)s in message from '
                            '%(domain)s:%(address)s',
                            {'version': msgVer, 'domain': transportDomain,
                             'address': transportAddress})

    return wholeMsg


def run_dispatcher(conf):
    transportDispatcher = AsyncoreDispatcher()
    transportDispatcher.registerRecvCbFun(callback)

    for num, cfg_string in enumerate(conf.alerts_interfaces):
        parsed = cfg_string.split(':')
        address = (parsed[0], int(parsed[1]) if len(parsed) == 2 else 162)
        transportDispatcher.registerTransport(
            udp.domainName + (num + 1,),
            udp.UdpSocketTransport().openServerMode(address))

    transportDispatcher.jobStarted(1)

    try:
        # Dispatcher will never finish as job#1 never reaches zero
        transportDispatcher.runDispatcher()
    except:
        transportDispatcher.closeDispatcher()
    raise
