# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import datetime

from oslo.config import cfg

from neutron.agent.linux import utils as linux_utils
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils

LOG = logging.getLogger(__name__)


STATUS_OPTS = [
    cfg.IntOpt('device_connection_timeout', default=30,
               help=_("Timeout value for connecting to a hosting device")),
    cfg.IntOpt('hosting_device_dead_timeout', default=300,
               help=_("The time in seconds until a backlogged hosting device "
                      "is presumed dead. This value should be set up high "
                      "enough to recover from a period of connectivity loss "
                      "or high load when the device may not be responding.")),
]

cfg.CONF.register_opts(STATUS_OPTS)


class DeviceStatus(object):
    """Device status and backlog processing."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DeviceStatus, cls).__new__(
                cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self.backlog_hosting_devices = {}

    def get_backlogged_hosting_devices(self):
        backlogged_hosting_devices = {}
        for (hd_id, data) in self.backlog_hosting_devices.items():
            backlogged_hosting_devices[hd_id] = {
                'affected routers': data['routers']}
        return backlogged_hosting_devices

    def is_hosting_device_reachable(self, resource):
        """Check the hosting device which hosts this resource is reachable.
        If the resource is not reachable,it is added to the backlog.
        """
        resource_id = resource['id']
        hd = resource['hosting_device']
        hd_id = hd['id']
        hd_mgmt_ip = hd['management_ip_address']
        #Modifying the 'created_at' to a date time object
        hd['created_at'] = datetime.datetime.strptime(hd['created_at'],
                                                      '%Y-%m-%d %H:%M:%S')

        if hd_id not in self.backlog_hosting_devices.keys():
            if self._is_pingable(hd_mgmt_ip):
                LOG.debug(_("Hosting device: %(hd_id)s @ %(ip)s for resource: "
                            "%(id)s is reachable."),
                          {'hd_id': hd_id, 'ip': hd['management_ip_address'],
                           'id': resource_id})
                return True
            LOG.debug(_("Hosting device: %(hd_id)s @ %(ip)s for resource: "
                        "%(id)s is NOT reachable."),
                      {'hd_id': hd_id, 'ip': hd['management_ip_address'],
                       'id': resource_id, })
            hd['backlog_insertion_ts'] = max(
                timeutils.utcnow(),
                hd['created_at'] +
                datetime.timedelta(seconds=hd['booting_time']))
            self.backlog_hosting_devices[hd_id] = {'hd': hd,
                                                   'routers': [resource_id]}
            LOG.debug(_("Hosting device: %(hd_id)s @ %(ip)s is now added "
                        "to backlog"), {'hd_id': hd_id,
                                        'ip': hd['management_ip_address']})
        else:
            self.backlog_hosting_devices[hd_id]['routers'].append(resource_id)

    def check_backlogged_hosting_devices(self):
        """"Checks the status of backlogged hosting devices.

        Has the intelligence to give allowance for the booting time for
        newly spun up instances. Sends back a response dict of the format:
        {'reachable': [<hd_id>,..], 'dead': [<hd_id>,..]}
        """
        response_dict = {'reachable': [],
                         'dead': []}
        LOG.debug(_("Current Backlogged hosting devices: %s"),
                  self.backlog_hosting_devices.keys())
        for hd_id in self.backlog_hosting_devices.keys():
            hd = self.backlog_hosting_devices[hd_id]['hd']
            if not timeutils.is_older_than(hd['created_at'],
                                           hd['booting_time']):
                LOG.info(_("Hosting device: %(hd_id)s @ %(ip)s hasn't passed "
                           "minimum boot time. Skipping it. "),
                         {'hd_id': hd_id, 'ip': hd['management_ip_address']})
                continue
            LOG.info(_("Checking hosting device: %(hd_id)s @ %(ip)s for "
                       "reachability."), {'hd_id': hd_id,
                                          'ip': hd['management_ip_address']})
            if self._is_pingable(hd['management_ip_address']):
                hd.pop('backlog_insertion_ts', None)
                del self.backlog_hosting_devices[hd_id]
                response_dict['reachable'].append(hd_id)
                LOG.info(_("Hosting device: %(hd_id)s @ %(ip)s is now "
                           "reachable. Adding it to response"),
                         {'hd_id': hd_id, 'ip': hd['management_ip_address']})
            else:
                LOG.info(_("Hosting device: %(hd_id)s @ %(ip)s still not "
                           "reachable "), {'hd_id': hd_id,
                                           'ip': hd['management_ip_address']})
                if timeutils.is_older_than(
                        hd['backlog_insertion_ts'],
                        cfg.CONF.hosting_device_dead_timeout):
                    LOG.debug(_("Hosting device: %(hd_id)s @ %(ip)s hasn't "
                                "been reachable for the last %(time)d "
                                "seconds. Marking it dead."),
                              {'hd_id': hd_id,
                               'ip': hd['management_ip_address'],
                               'time': cfg.CONF.hosting_device_dead_timeout})
                    response_dict['dead'].append(hd_id)
                    hd.pop('backlog_insertion_ts', None)
                    del self.backlog_hosting_devices[hd_id]
        LOG.debug(_("Response: %s"), response_dict)
        return response_dict

    def _is_pingable(self, ip):
        """Checks whether an IP address is reachable by pinging.

        Use linux utils to execute the ping (ICMP ECHO) command.
        Sends 5 packets with an interval of 0.2 seconds and timeout of 1
        seconds. Runtime error implies unreachability else IP is pingable.
        :param ip: IP to check
        :return: bool - True or False depending on pingability.
        """
        ping_cmd = ['ping',
                    '-c', '5',
                    '-W', '1',
                    '-i', '0.2',
                    ip]
        try:
            linux_utils.execute(ping_cmd, check_exit_code=True)
        except RuntimeError:
            LOG.warn(_("Cannot ping ip address: %s"), ip)
            return False
        return True