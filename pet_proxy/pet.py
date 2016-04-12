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
import struct
import uuid

import six

from pet_proxy import exception


_SOURCE_TYPES = {
    0x00: 'Platform Firmware',
    0x08: 'SMI Handler',
    0x10: 'ISV System Management Software',
    0x18: 'Alert ASIC',
    0x20: 'IPMI',
    0x28: 'BIOS Vendor',
    0x30: 'System Board Set Vendor',
    0x38: 'System Integrator',
    0x40: 'Third Party Add-in',
    0x48: 'OSV',
    0x50: 'NIC',
    0x58: 'System Management Card'
}


_SEVERITIES = {
    0x00: 'unspecified',
    0x01: 'Monitor',
    0x02: 'Information',
    0x04: 'OK condition',
    0x08: 'Non-critical condition',
    0x10: 'Critical condition',
    0x20: 'Non-recoverable condition'
}


_GENERIC_ENTITIES ={
    0: 'Unspecified',
    1: 'Other',
    2: 'Unknown',
    3: 'Processor',
    4: 'Disk or disk bay',
    5: 'Peripheral bay',
    6: 'System management module',
    7: 'System board',
    8: 'Memory module',
    9: 'Processor module',
    10: 'Power supply',
    11: 'Add-in card',
    12: 'Front panel board',
    13: 'Back panel board',
    14: 'Power system board',
    15: 'Drive backplane',
    16: 'System internal expansion board',
    17: 'Other system board',
    18: 'Processor board',
    20: 'Power unit',
    21: 'Power module',
    22: 'Power management',
    23: 'Chassis back panel board',
    24: 'System chassis',
    25: 'Sub-chassis',
    26: 'Other chassis board',
    27: 'Disk Drive Bay',
    28: 'Peripheral Bay',
    29: 'Device Bay',
    30: 'Fan / cooling device',
    31: 'Cooling unit',
    32: 'Cable / interconnect',
    33: 'Memory device',
    34: 'System Management Software',
    35: 'BIOS',
    36: 'Operating System',
    37: 'System Bus',
    38: 'Group'
}


_GENERIC_EVENTS = {
    # NOTE: some FW uses 0x00 for test events
    0x00: {
        0x00: 'Reserved / Test'
    },
    0x01: {
        0x00: 'Lower Non-critical - going low',
        0x01: 'Lower Non-critical - going high',
        0x02: 'Lower Critical - going low',
        0x03: 'Lower Critical - going high',
        0x04: 'Lower Non-recoverable - going low',
        0x05: 'Lower Non-recoverable - going high',
        0x06: 'Upper Non-critical - going low',
        0x07: 'Upper Non-critical - going high',
        0x08: 'Upper Critical - going low',
        0x09: 'Upper Critical - going high',
        0x0A: 'Upper Non-recoverable - going low',
        0x0B: 'Upper Non-recoverable - going high'
    },
    0x02: {
        0x00: 'Transition to Idle',
        0x01: 'Transition to Active',
        0x02: 'Transition to Busy'
    },
    0x03: {
        0x00: 'State Deasserted',
        0x01: 'State Asserted'
    },
    0x04: {
        0x00: 'Predictive Failure Deasserted',
        0x01: 'Predictive Failure Asserted'
    },
    0x05: {
        0x00: 'Limit Not Exceeded',
        0x01: 'Limit Exceeded'
    },
    0x06: {
        0x00: 'Performance Met',
        0x01: 'Performance Lags'
    },
    0x07: {
        0x00: 'transition to OK',
        0x01: 'transition to Non-Critical from OK',
        0x02: 'transition to Critical from Less Severe',
        0x03: 'transition to Non-recoverable from Less Severe',
        0x04: 'transition to Non-Critical from More Severe',
        0x05: 'transition to Critical from Non-recoverable',
        0x06: 'transition to Non-recoverable',
        0x07: 'Monitor',
        0x08: 'Informational'
    },
    0x08: {
        0x00: 'Device Removed / Device Absent',
        0x01: 'Device Inserted / Device Present'
    },
    0x09: {
        0x00: 'Device Disabled',
        0x01: 'Device Enabled'
    },
    0x0A: {
        0x00: 'transition to Running',
        0x01: 'transition to In Test',
        0x02: 'transition to Power Off',
        0x03: 'transition to On Line',
        0x04: 'transition to Off Line',
        0x05: 'transition to Off Duty',
        0x06: 'transition to Degraded',
        0x07: 'transition to Power Save',
        0x08: 'Install Error'
    },
    0x0B: {
        0x00: 'Redundancy Regained',
        0x01: 'Redundancy Lost',
        0x02: 'Redundancy Degraded'
    },
    # ACPI device power states
    0x0C: {
        0x00: 'D0',
        0x01: 'D1',
        0x02: 'D2',
        0x03: 'D3'
    }
}


_SENSORS_EVENTS = {
    # NOTE: some FW uses 0x00 for test events
    0x00: ('Reserved / Test', None),
    0x01: ('Temperature', None),
    0x01: ('Voltage', None),
    0x03: ('Current', None),
    0x04: ('Fan', None),
    0x05: ('Physical Security',
           {
                0x00: 'General Chassis Intrusion',
                0x01: 'Drive Bay Intrusion',
                0x02: 'I/O Card area Intrusion',
                0x03: 'Processor area Intrusion',
                0x04: 'LAN Leash Lost',
                0x05: 'Unauthorized Dock/Undock'
            }),
    0x06: ('Platform Security Violation Attempt',
           {
                0x00: 'Secure Mode Violation Attempt',
                0x01: 'Pre-boot Password Violation - user password',
                0x02: 'Pre-boot Password Violation Attempt - setup password',
                0x03: 'Pre-boot Password Violation - network boot password',
                0x04: 'Other pre-boot Password Violation',
                0x05: 'Out-of-band Access Password Violation'
            }),
    0x07: ('Processor',
           {
                0x00: 'IERR',
                0x01: 'Thermal Trip',
                0x02: 'FRB1/BIST Failure',
                0x03: 'FRB2/Hang in POST Failure',
                0x04: 'FRB3/Processor Startup/Initialization failure '
                      '(CPU did not start)',
                0x05: 'Configuration Error (for DMI)',
                0x06: 'SM BIOS "Uncorrectable CPU-complex Error"',
                0x07: 'Processor Presence Detected',
                0x08: 'Processor Disabled',
                0x09: 'Terminator Presence Detected'
           }),
    0x08: ('Power Supply', {
                0x00: 'Presence Detected',
                0x01: 'Power Supply Failure Detected',
                0x02: 'Predictive Failure Asserted'
           }),
    0x09: ('Power Unit', {
                0x00: 'Power Off / Power Down',
                0x01: 'Power Cycle',
                0x02: '240VA Power Down',
                0x03: 'Interlock Power Down',
                0x04: 'A/C Lost',
                0x05: 'Soft Power Control Failure (unit did not respond to '
                      'request to turn on)',
                0x06: 'Power Unit Failure Detected'
           }),
    0x0A: ('Cooling Device', None),
    0x0B: ('Other Units-based Sensor', None),
    0x0C: ('Memory', {
                0x00: 'Correctable ECC',
                0x01: 'Uncorrectable ECC',
                0x02: 'Parity',
                0x03: 'Memory Scrub Failed (stuck bit)'
           }),
    0x0D: ('Drive Slot (Bay)', None),
    0x0E: ('POST Memory Resize', None),
    0x0F: ('POST Error', None),
    0x10: ('Event Logging Disabled', {
                0x00: 'Correctable Memory Error Logging Disabled',
                0x01: 'Event "Type" Logging Disabled',
                0x02: 'Log Area Reset/Cleared',
                0x03: 'All Event Logging Disabled'
          }),
    0x11: ('Watchdog 1', {
                0x00: 'BIOS Watchdog Reset',
                0x01: 'OS Watchdog Reset',
                0x02: 'OS Watchdog Shut Down',
                0x03: 'OS Watchdog Power Down',
                0x04: 'OS Watchdog Power Cycle',
                0x05: 'OS Watchdog NMI',
                0x06: 'OS Watchdog Expired, status only',
                0x07: 'OS Watchdog Pre-timeout Interrupt, non-NMI'
          }),
    0x12: ('System Event', {
                0x00: 'System Reconfigured',
                0x01: 'OEM System Boot Event',
                0x02: 'Undetermined system hardware failure'
          }),
    0x13: ('Critical Interrupt', {
                0x00: 'Front Panel NMI',
                0x01: 'Bus Timeout',
                0x02: 'I/O Channel Check NMI',
                0x03: 'Software NMI',
                0x04: 'PCI PERR',
                0x05: 'PCI SERR',
                0x06: 'EISA Fail Safe Timeout',
                0x07: 'Bus Correctable Error',
                0x08: 'Bus Uncorrectable Error',
                0x09: 'Fatal NMI'
          }),
    0x14: ('Button', None),
    0x15: ('Module / Board', None),
    0x16: ('Microcontroller / Coprocessor', None),
    0x17: ('Add-in Card', None),
    0x18: ('Chassis', None),
    0x19: ('Chip Set', None),
    0x1A: ('Other FRU', None),
    0x1B: ('Cable / Interconnect', None),
    0x1C: ('Terminator', None),
    0x1D: ('System Boot Initiated', {
                0x00: 'Initiated by power up',
                0x01: 'Initiated by hard reset',
                0x02: 'Initiated by warm reset',
                0x03: 'User requested PXE boot',
                0x04: 'Automatic boot to diagnostic'
          }),
    0x1E: ('Boot Error', {
                0x00: 'No bootable media',
                0x01: 'Non-bootable diskette left in drive',
                0x02: 'PXE Server not found',
                0x03: 'Invalid boot sector',
                0x04: 'Timeout waiting for user selection of boot source'
          }),
    0x1F: ('OS Boot', {
                0x00: 'A: boot completed',
                0x01: 'C: boot completed',
                0x02: 'PXE boot completed',
                0x03: 'Diagnostic boot completed',
                0x04: 'CD-ROM boot completed',
                0x05: 'ROM boot completed',
                0x06: 'Boot completed - boot device not specified'
          }),
    0x20: ('OS Critical Stop', {
                0x00: 'Stop during OS load / initialization',
                0x01: 'Run-time Stop'
          }),
    0x21: ('Slot / Connector', {
                0x00: 'Fault Status asserted',
                0x01: 'Identify Status asserted',
                0x02: 'Slot / Connector Device installed/attached',
                0x03: 'Slot / Connector Ready for Device Installation',
                0x04: 'Slot/Connector Ready for Device Removal',
                0x05: 'Slot Power is Off',
                0x06: 'Slot / Connector Device Removal Request',
                0x07: 'Interlock asserted'
          }),
    0x22: ('System ACPI Power State', {
                0x00: 'S0 / G0 "working"',
                0x01: 'S1 "sleeping with system h/w & processor context '
                      'maintained"',
                0x02: 'S2 "sleeping, processor context lost"',
                0x03: 'S3 "sleeping, processor & h/w context lost, memory '
                      'retained."',
                0x04: 'S4 "non-volatile sleep / suspend-to disk"',
                0x05: 'S5 / G2 "soft-off"',
                0x06: 'S4 / S5 soft-off, particular S4 / S5 state cannot be '
                      'determined',
                0x07: 'G3 / Mechanical Off',
                0x08: 'Sleeping in an S1, S2, or S3 states',
                0x09: 'G1 sleeping (S1-S4 state cannot be determined)',
          }),
    0x23: ('Watchdog 2', {
                0x00: 'Timer expired, status only',
                0x01: 'Hard Reset',
                0x02: 'Power Down',
                0x03: 'Power Cycle',
                0x08: 'Timer interrupt'
          }),
    0x24: ('Platform Alert', {
                0x00: 'Platform generated page',
                0x01: 'Platform generated LAN alert',
                0x02: 'Platform Event Trap generated, formatted per IPMI PET '
                      'specification',
                0x03: 'Platform generated SNMP trap, OEM format'
          }),
    0x25: ('Entity Presence', {
                0x00: 'Entity Present',
                0x01: 'Entity Absent'
          }),
    0x26: ('Monitor ASIC / IC', None),
    0x27: ('LAN', {
                0x00: 'LAN Heartbeat Lost'
        })
}


_PET_BINDING_FIELDS = ('sequence', 'local_timestamp', 'utc_offset',
                       'trap_source', 'event_source', 'severity',
                       'sensor_device', 'sensor_number', 'entity',
                       'entity_instance', 'language_code', 'manufacturer_id',
                       'system_id')


_PET_TIMESTAMP_OFFSET = 883612800 # 0:00 1/1/98


def _hex(x):
    return '0x{:02X}'.format(x)


def _hexinfo(x):
    return ' ' + _hex(x)


def _handle_parsing_error(func):
    @six.wraps(func)
    def wrapper(input_data):
        try:
            return func(input_data)
        except (IndexError, KeyError, struct.error):
            raise exception.PETProxyException('Invalid/corrupted data in SNMP'
                                              ' trap')

    return wrapper


def _calculate_timestamp(pet_timestamp, utc_offset):
    offset_sec = utc_offset * 60 if utc_offset != -1 else 0
    timestamp = pet_timestamp + _PET_TIMESTAMP_OFFSET - offset_sec
    return datetime.datetime.utcfromtimestamp(timestamp).isoformat()


def _get_source(source_byte):
    if source_byte == 0xFF:
        return 'Unspecified'
    return _SOURCE_TYPES[source_byte & 0xF8]


def _get_entity(entity_byte):
    if 0x90 <= entity_byte <= 0xAF:
        return 'Chassis-specific' + _hexinfo(entity_byte)
    if 0xB0 <= entity_byte <= 0xCF:
        return 'Board-set specific' + _hexinfo(entity_byte)
    if 0xD0 <= entity_byte <= 0xFF:
        return 'OEM defined' + _hexinfo(entity_byte)

    return _GENERIC_ENTITIES[entity_byte]


@_handle_parsing_error
def get_alert_string(oem_fields):
    # TODO: use all fields
    field_index = oem_fields.find(b'\x80')
    if field_index != -1:
        encoding_length = oem_fields[field_index + 1]
        # record_type = oem_fields[field_index + 2]
        length = encoding_length & 0x3F
        record_data = oem_fields[field_index + 3:field_index + 3 + length]
        return record_data.decode()


@_handle_parsing_error
def parse_pet_values(byte_str):
    parsed_values = {}
    bytes_value = bytearray(byte_str)
    system_guid = str(uuid.UUID(bytes_le=six.binary_type(bytes_value[:16])))
    parsed_values['system_guid'] = system_guid
    pet_values = struct.unpack('!HIhBBBBBBBxxxxxxxxBIH', bytes_value[16:46])
    bindings = {field: value for field, value in
                zip(_PET_BINDING_FIELDS, pet_values)}
    parsed_values['sequence'] = bindings['sequence']
    parsed_values['timestamp'] = _calculate_timestamp(
                          bindings['local_timestamp'], bindings['utc_offset'])
    parsed_values['trap_source'] = (_get_source(bindings['trap_source']) +
                                    _hexinfo(bindings['trap_source']))
    parsed_values['event_source'] = (_get_source(bindings['event_source']) +
                                     _hexinfo(bindings['event_source']))
    parsed_values['severity'] = _SEVERITIES[bindings['severity']]
    parsed_values['sensor_device'] = _hex(bindings['sensor_device'])
    parsed_values['sensor_number'] = _hex(bindings['sensor_number'])
    parsed_values['entity'] = _get_entity(bindings['entity'])
    parsed_values['entity_instance'] = _hex(bindings['entity_instance'])
    # only 3 bytes used
    parsed_values['event_data'] = ' '.join([_hex(x) for x in
                                           bytes_value[31:34]])
    parsed_values['language_code'] = bindings['language_code']
    parsed_values['manufacturer_id'] = bindings['manufacturer_id']
    parsed_values['system_id'] = bindings['system_id']

    oem_fields = bytes_value[46:]
    if oem_fields and bytes_value[46] != 0xC1:
        bindings['oem_fields'] = ' '.join([_hex(x) for x in oem_fields])
        alert_string = get_alert_string(oem_fields)
        bindings['alert_string'] = alert_string if alert_string else ''


    return parsed_values


@_handle_parsing_error
def parse_specific_trap(integer_trap):
    parsed_values = {}
    offset = integer_trap & 0x0F
    event_type = (integer_trap >> 8) & 0xFF
    sensor_type = integer_trap >> 16
    parsed_values['assertion'] = ('Deassertion Event' if integer_trap & 0x80
                                  else 'Assertion Event')
    hex_sensor = _hexinfo(sensor_type)
    hex_offset = _hexinfo(offset)
    if 0xC0 <= sensor_type <= 0xFF:
        parsed_values['sensor_type'] = 'OEM specific' + hex_sensor
    else:
        parsed_values['sensor_type'] = (_SENSORS_EVENTS[sensor_type][0] +
                                        hex_sensor)

    if offset == 0x0F:
        parsed_values['event_offset'] = 'Unspecified 0x0F'
    elif 0x00 <= event_type <= 0x0C:
        # generic events
        parsed_values['event_offset'] = (_GENERIC_EVENTS[event_type][offset] +
                                         hex_offset)
    elif event_type == 0x6F:
        # sensor specific
        parsed_values['event_offset'] = (_SENSORS_EVENTS[sensor_type][1][offset]
                                         + hex_offset)
    elif 0x70 <= event_type <= 0x7F:
        parsed_values['event_offset'] = 'OEM specific' + hex_offset
    else:
        raise exception.PETProxyException('Invalid event type')

    return parsed_values
