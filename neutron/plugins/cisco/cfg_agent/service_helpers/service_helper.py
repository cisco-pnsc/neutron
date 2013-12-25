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

from abc import ABCMeta
from abc import abstractmethod
import Queue
import six
import threading

from neutron.common import rpc as q_rpc
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


@six.add_metaclass(ABCMeta)
class ServiceHelperBase(object):

    def __init__(self):
        self._observers = []

    def register(self, observer):
        LOG.debug(_("Attaching observer: %(ob)s to subject: %(sub)s"),
                  {'ob': observer.__class__.__name__,
                   'sub': self.__class__.__name__})
        if observer not in self._observers:
            self._observers.append(observer)
        else:
            raise ValueError(_("Observer: %(ob)s is already registered to "
                             "subject: %(sub)s"),
                             {'ob': observer.__class__.__name__,
                              'sub': self.__class__.__name__})

    def unregister(self, observer):
        LOG.debug(_("Dettaching observer: %(ob)s to subject: %(sub)s"),
                  {'ob': observer.__class__.__name__,
                   'sub': self.__class__.__name__})
        if observer in self._observers:
            self._observers.remove(observer)
        else:
            raise ValueError(_("Observer: %(ob)s is not attached to "
                               "subject: %(sub)s"),
                             {'ob': observer.__class__.__name__,
                              'sub': self.__class__.__name__})

    def notify(self, resource, **kwargs):
        """Calls all observers attached to th given subject."""
        LOG.debug(_("Notifying all observers of this subject"))
        for observer in self._observers:
            LOG.debug(_("Notifying observer: %s"), observer.__class__.__name__)
            observer.update(resource, **kwargs)

    def update(self, resource, **kwargs):
        LOG.debug(_("Update received"))

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this service."""
        return q_rpc.PluginRpcDispatcher([self])

    @abstractmethod
    def process_service(self, *args, **kwargs):
        raise NotImplementedError


class QueueMixin(object):
    def __init__(self):
        super(QueueMixin, self).__init__()
        self._queues = {}
        self._lock = threading.RLock()

    def enqueue(self, qname, data):
        if qname not in self._queues:
            self._queues[qname] = Queue.Queue()
        with self._lock:
            queue = self._queues[qname]
            queue.put(data)

    def dequeue(self, qname):
        if qname not in self._queues:
            raise ValueError(_("queue %s is not defined"), qname)
        with self._lock:
            return self._queues[qname].get()