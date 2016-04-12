########################################
Platform Event Trap proxy for OpenStack
########################################

This is proof of concept of Platform Event Trap (PET) proxy service.
It converts PET from hardware to OpenStack notification.


Configuration
=============

Example of config file::

    [DEFAULT]
    rpc_backend = rabbit
    use_syslog = False
    debug = True
    host=test-host
    api_url=http://192.168.122.107:6385/v1
    alerts_interfaces=192.168.201.2,

    [oslo_messaging_rabbit]
    rabbit_userid = stackrabbit
    rabbit_password = devel
    rabbit_hosts = 192.168.122.107
