__author__ = 'nalle'

'''Does not iterate over multiple instances in a request.
Assumes that the plugins forwards a list of hosts'''
from oslo.config import cfg

from neutron.openstack.common import log as logging
from neutron.plugins.cisco.l3.scheduler.filters import filters_base as filters
from neutron.plugins.cisco.l3.scheduler import weights
from neutron.plugins.cisco.l3.db.filter_chain_db import FilterChain as Fc

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

filter_scheduler_opts = [
    cfg.MultiStrOpt('scheduler_available_filters',
                    default=['neutron.plugins.cisco.l3.scheduler.filters.all_filters'],
                    help='Filter classes available to the scheduler'),

    cfg.ListOpt('scheduler_weight_classes',
                default=['neutron.plugins.cisco.l3.scheduler.weights.all_weighers'],
                help='Which weight class names to use for weighing hosts')
]

CONF.register_opts(filter_scheduler_opts)


class FilterScheduler(object):
    def __init__(self):

        self.filter_handler = filters.HostFilterHandler()
        self.filter_classes = self.filter_handler.get_matching_classes(
            CONF.scheduler_available_filters)

        self.weight_handler = weights.HostWeightHandler()
        self.weight_classes = self.weight_handler.get_matching_classes(
            CONF.weight_classes)

    def schedule_instance(self, context, resource, hosts, chain_id, weight_properties):

        filter_chain = Fc.get_filter_chain(context, chain_id)
        if filter_chain is None:
            #EXCPETION - filter chain does not exist in database
            pass
        good_filter_chain = self._choose_host_filters(filter_chain)
        try:
             weighed_host = self._schedule(context, resource,
                                       hosts, weight_properties, good_filter_chain)
        except IndexError:
            # FIX - raise exception.NoValidHost(reason="")
            pass

        resource_id = resource.get('id')

            #TO_DO BIND INSTANCE TO HOST.
            #We got a host from weighed_hosts
            #we got a resource
            #Bind in db, look at Bobs code

    def _schedule(self, context, resource, hosts,
                  weight_properties, filter_chain=None, ):

        filtered_hosts = self.get_filtered_hosts(resource, hosts,
                                                 filter_chain)
        if not filtered_hosts:
            # All hosts failed all filters
            return None

        chosen_host = self.get_weighed_hosts(filtered_hosts,
                                             weight_properties)
        if not chosen_host:
            return None

        return chosen_host

    def get_filtered_hosts(self, resource, hosts, filter_chain):
        """Filter hosts and return only ones passing all filters."""
        return self.filter_handler.get_filtered_objects(resource, hosts, filter_chain)

    def get_weighed_hosts(self, hosts, weight_functions):
        """Weigh the hosts."""

        if weight_functions is None:
            weight_functions = self.weight_classes

        return self.weight_handler.get_weighed_objects(hosts, weight_functions)

    def _choose_host_filters(self, filter_cls_names):
        """Remove any bad filters in the filter chain"""

        if filter_cls_names is None:
            filter_cls_names = CONF.scheduler_default_filters
        if not isinstance(filter_cls_names, (list, tuple)):
            filter_cls_names = [filter_cls_names]
        cls_map = dict((cls.__name__, cls) for cls in self.filter_classes)
        good_filters = []
        bad_filters = []
        for filter_name in filter_cls_names:
            if filter_name not in cls_map:
                bad_filters.append(filter_name)
                continue
            good_filters.append(cls_map[filter_name])

        return good_filters