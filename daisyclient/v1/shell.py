# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
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

from __future__ import print_function

import copy
import functools
import pprint
import os
import six
import sys

from oslo_utils import encodeutils
from oslo_utils import strutils

from daisyclient.common import progressbar
from daisyclient.common import utils
from daisyclient import exc
import daisyclient.v1.hosts
import daisyclient.v1.clusters
import daisyclient.v1.cluster_hosts
import daisyclient.v1.components
import daisyclient.v1.services
import daisyclient.v1.roles
import daisyclient.v1.config_files
import daisyclient.v1.config_sets
import daisyclient.v1.networks
import daisyclient.v1.configs
import daisyclient.v1.uninstall
import daisyclient.v1.update
from daisyclient.v1 import param_helper

_bool_strict = functools.partial(strutils.bool_from_string, strict=True)


def _daisy_show(daisy, max_column_width=80):
    info = copy.deepcopy(daisy._info)

    utils.print_dict(info, max_column_width=max_column_width)


@utils.arg('name', metavar='<NAME>',
           help='node name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='node description to be added.')
@utils.arg('--resource-type', metavar='<RESOURCE_TYPE>',
           help='node resource type to be added, supported type are "baremetal", "server" and "docker".\
                 "baremetal" is traditional physical server ,\
                 "server" is virtual machine and \
                 "docker" is container created by docker.')
@utils.arg('--dmi-uuid', metavar='<DMI_UUID>',
           help='node dmi uuid to be added.')
@utils.arg('--ipmi-user', metavar='<IPMI_USER>',
           help='ipmi user name to be added.')
@utils.arg('--ipmi-passwd', metavar='<IPMI_PASSWD>',
           help='ipmi user of password to be added.')
@utils.arg('--ipmi-addr', metavar='<IPMI_ADDR>',
           help='ipmi ip to be added.')
@utils.arg('--role', metavar='<ROLE>',nargs='+',
           help='name of node role to be added.')
#@utils.arg('--status', metavar='<STATUS>',
#           help='node status to be added.')           
@utils.arg('--cluster', metavar='<CLUSTER>',
           help='id of cluster that the node will be added.')
@utils.arg('--os-version', metavar='<OS_VERSION>',
           help='os version of the host.')
@utils.arg('--os-status', metavar='<OS_STATUS>',
           help='os status of the host.')
@utils.arg('--interfaces', metavar='<type=ether,name=eth5,mac=4C:AC:0A:AA:9C:EF,ip=networkname1:ip1_networkname2:ip2_networkname3:ip3,netmask=netmask,gateway=gateway,is_deployment=False,assigned_networks=networkname1_networkname2_networkname3,pci=pci,mode=mode,slaves=eth0_eth1>',
           nargs='+',
           help='node network interface detail.')
def do_host_add(gc, args):
    """Add a host."""
    if args.cluster:
        cluster = utils.find_resource(gc.clusters, args.cluster)
        if cluster and cluster.deleted:
            msg = "No cluster with an ID of '%s' exists." % cluster.id
            raise exc.CommandError(msg)
    # if args.role:
        # role = utils.find_resource(gc.roles, args.role)
        # if role and role.deleted:
            # msg = "No role with an ID of '%s' exists." % role.id
            # raise exc.CommandError(msg)
    interface_list = []
    if args.interfaces: 
        for interfaces in args.interfaces:
            interface_info = {"pci":"", "mode":"", "gateway":"", "type": "", "name": "", "mac": "", "ip": "", "netmask": "", "assigned_networks": "", "slaves":"", "is_deployment":""}
            for kv_str in interfaces.split(","):
                try:                                        
                    k, v = kv_str.split("=", 1)
                except ValueError:
                    raise exc.CommandError("interface error")

                if k in interface_info:
                    interface_info[k] = v
                    if k == "ip":
                        ip_list = interface_info['ip'].split("_")
                        interface_info['ip'] = ip_list
                    if k == "assigned_networks":
                        network_list = interface_info['assigned_networks'].split("_")
                        # for network_id in network_list:
                            # network = utils.find_resource(gc.networks, network_id)
                            # if network and network.deleted:
                                # msg = "No network with an ID of '%s' exists." % network.id
                                # raise exc.CommandError(msg)
                        interface_info['assigned_networks'] = network_list
                    if k == "slaves":
                        slaves_list = interface_info['slaves'].split("_", 1)
                        interface_info['slaves'] = slaves_list
            interface_list.append(interface_info)
        args.interfaces = interface_list
                        
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.hosts.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    host = gc.hosts.add(**fields)

    _daisy_show(host)
    
@utils.arg('hosts', metavar='<HOST>', nargs='+',
           help='ID of host(s) to delete.')
def do_host_delete(gc, args):
    """Delete specified host(s)."""

    for args_host in args.hosts:
        host = utils.find_resource(gc.hosts, args_host)
        if host and host.deleted:
            msg = "No host with an ID of '%s' exists." % host.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting host delete for %s ...' %
                      encodeutils.safe_decode(args_host), end=' ')
            gc.hosts.delete(host)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete host %s' % (e, args_host))

@utils.arg('host', metavar='<HOST>', help='ID of host to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of host.')
@utils.arg('--resource-type', metavar='<RESOURCE_TYPE>',
           help='node resource type to be added, supported type are "baremetal", "server" and "docker".\
                 "baremetal" is traditional physical server ,\
                 "server" is virtual machine and \
                 "docker" is container created by docker.')
@utils.arg('--dmi-uuid', metavar='<DMI_UUID>',
           help='node dmi uuid for the host.')
@utils.arg('--ipmi-user', metavar='<IPMI_USER>',
           help='ipmi user name for the host.')
@utils.arg('--ipmi-passwd', metavar='<IPMI_PASSWD>',
           help='ipmi user of password for the host.')
@utils.arg('--ipmi-addr', metavar='<IPMI_ADDR>',
           help='ipmi ip for the host.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of host.')
@utils.arg('--root-disk', metavar='<ROOT_DISK>',
           help='the disk used to install OS.')           
@utils.arg('--root-lv-size', metavar='<ROOT_LV_SIZE>',
           help='the size of root_lv(M).')
@utils.arg('--swap-lv-size', metavar='<SWAP_LV_SIZE>',
           help='the size of swap_lv(M).')
@utils.arg('--root-pwd', metavar='<ROOT_PWD>',
           help='the passward of os.')
@utils.arg('--cluster', metavar='<CLUSTER>',
           help='id of cluster that the node will be added.')
@utils.arg('--os-version', metavar='<OS_VERSION>',
           help='os version for the host.')
@utils.arg('--os-status', metavar='<OS_STATUS>',
           help='os status for the host.')
#@utils.arg('--status', metavar='<STATUS>',
#           help='node status for the host.')           
@utils.arg('--role', metavar='<ROLE>',nargs='+',
           help='name of node role for the host.')
@utils.arg('--interfaces', metavar='<type=ether,name=eth5,mac=4C:AC:0A:AA:9C:EF,ip=networkname1:ip1_networkname2:ip2_networkname3:ip3,netmask=netmask,gateway=gateway,is_deployment=False,assigned_networks=networkname1_networkname2_networkname3,pci=pci,mode=mode,slaves=eth0_eth1>',
           nargs='+',
           help='node network interface detail.')
def do_host_update(gc, args):
    """Update a specific host."""
    # Filter out None values
    if args.cluster:
        cluster = utils.find_resource(gc.clusters, args.cluster)
        if cluster and cluster.deleted:
            msg = "No cluster with an ID of '%s' exists." % cluster.id
            raise exc.CommandError(msg)
    interface_list = []
    if args.interfaces: 
        for interfaces in args.interfaces:
            interface_info = {"pci":"", "mode":"", "gateway":"", "type": "", "name": "", "mac": "", "ip": "", "netmask": "", "mode": "","assigned_networks": "", "slaves":"", "is_deployment":""}
            for kv_str in interfaces.split(","):                                
                try:                                        
                    k, v = kv_str.split("=", 1)
                except ValueError:                                        
                    raise exc.CommandError("interface error")
                if k in interface_info:                                        
                    interface_info[k] = v
                    if k == "ip":
                        ip_list = interface_info['ip'].split("_")
                        interface_info['ip'] = ip_list
                    if k == "assigned_networks":
                        network_list = interface_info['assigned_networks'].split("_")
                        # for network_id in network_list:
                            # network = utils.find_resource(gc.networks, network_id)
                            # if network and network.deleted:
                                # msg = "No network with an ID of '%s' exists." % network.id
                                # raise exc.CommandError(msg)
                        interface_info['assigned_networks'] = network_list
                    if k == "slaves":
                        slaves_list = interface_info['slaves'].split("_", 1)
                        interface_info['slaves'] = slaves_list
            interface_list.append(interface_info)
        args.interfaces = interface_list        
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    host_arg = fields.pop('host')
    host = utils.find_resource(gc.hosts, host_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.hosts.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    host = gc.hosts.update(host, **fields)
    _daisy_show(host)


@utils.arg('--name', metavar='<NAME>',
           help='Filter hosts to those that have this name.')
@utils.arg('--status', metavar='<STATUS>',
           help='Filter hosts systus.')
@utils.arg('--cluster-id', metavar='<CLUSTER_ID>',
           help='Filter by cluster_id.')
@utils.arg('--page-size', metavar='<SIZE>', default=None, type=int,
           help='Number of hosts to request in each paginated request.')
@utils.arg('--sort-key', default='name',
           choices=daisyclient.v1.hosts.SORT_KEY_VALUES,
           help='Sort host list by specified field.')
@utils.arg('--sort-dir', default='asc',
           choices=daisyclient.v1.hosts.SORT_DIR_VALUES,
           help='Sort host list in specified direction.')
def do_host_list(gc, args):
    """List hosts you can access."""
    filter_keys = ['name', 'status', 'cluster_id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])

    kwargs = {'filters': filters}
    if args.page_size is not None:
        kwargs['page_size'] = args.page_size

    kwargs['sort_key'] = args.sort_key
    kwargs['sort_dir'] = args.sort_dir

    hosts = gc.hosts.list(**kwargs)

    columns = ['ID', 'Name','Description', 'resource_type', 'status', 'os_progress','os_status','messages']
    if filters.has_key('cluster_id'):
        role_columns = ['role_progress','role_status', 'role_messages']
        columns += role_columns

    utils.print_list(hosts, columns)
 
@utils.arg('id', metavar='<ID>',
           help='Filter host to those that have this id.')
def do_host_detail(gc, args):
    """List host you can access."""    
    host = utils.find_resource(gc.hosts, args.id)
    _daisy_show(host)

# @utils.arg('name', metavar='<NAME>',
#            help='Cluster name to be added.')
# @utils.arg('--nodes', metavar='<NODES>',nargs='+',
#            help='id of cluster nodes to be added.')
# @utils.arg('description', metavar='<DESCRIPTION>',
#            help='Cluster description to be added.')
# @utils.arg('--networks', metavar='<NETWORKS>',nargs='+',
#            help='id of cluster networks.')
# @utils.arg('--floating_ranges', metavar='<FLOATING_RANGES>',nargs='+',
#            help='Cluster floating ranges:"172.16.0.130","172.16.0.254"')
# @utils.arg('--dns_nameservers', metavar='<DNS_NAMESERVERS>',nargs='+',
#            help='Cluster dns nameservers:"8.8.4.4" "8.8.8.8" ')
# @utils.arg('--net_l23_provider', metavar='<NET_123_PROVIDER>',
#            help='Cluster net_l23_provider.')
# @utils.arg('--base_mac', metavar='<BASE_MAC>',
#            help='Cluster base_mac.')
# @utils.arg('--internal_gateway', metavar='<INTERNAL_GATEWAY>',
#            help='Cluster internal gateway.')
# @utils.arg('--internal_cidr', metavar='<INTERNAL_CIDR>',
#            help='Cluster internal_cidr.')
# @utils.arg('--external_cidr', metavar='<EXTERNAL_CIDR>',
#            help='Cluster external cidr.')
# @utils.arg('--gre_id_range', metavar='<GRE_ID_RANGE>',nargs='+',
#            help='Cluster gre_id_range. 2 65535')
# @utils.arg('--vlan_range', metavar='<VLAN_RANGE>',nargs='+',
#            help='Cluster vlan_range.1000 1030')
# @utils.arg('--vni_range', metavar='<VNI_RANGE>',nargs='+',
#            help='Cluster vNI range.1000 1030')
# @utils.arg('--segmentation_type', metavar='<SEGMENTATION_TYPE>',
#            help='Cluster segmentation_type.')
# @utils.arg('--public_vip', metavar='<PUBLIC_VIP>',
#            help='Cluster public vip.')
@utils.arg('params_file_path', metavar='<PARAMS_FILE_PATH>',
           help="""Template file path.
                   Run \"daisy params-helper params_file_path\" for the template content.
                   Then save the output to a template file.Just use this path.""")
def do_cluster_add(gc, args):
    """Add a cluster."""
    fields = None
    if not args.params_file_path:
        if args.nodes:
            for arg_node in args.nodes:
                host = utils.find_resource(gc.hosts, arg_node)
                if host and host.deleted:
                    msg = "No host with an ID of '%s' exists." % host.id
                    raise exc.CommandError(msg)
        if args.networks:
            for arg_network in args.networks:
                network = utils.find_resource(gc.networks, arg_network)
                if network and network.deleted:
                    msg = "No network with an ID of '%s' exists." % network.id
                    raise exc.CommandError(msg)
        range_list = []
        if args.floating_ranges:
            for floating_ranges in args.floating_ranges:
                float_ip_list = floating_ranges.split(",")
                range_list.append(float_ip_list)
        args.floating_ranges = range_list
        fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

        # Filter out values we can't use
        CREATE_PARAMS = daisyclient.v1.clusters.CREATE_PARAMS
        fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    else:
        fields = param_helper._read_template_file(args)

    cluster = gc.clusters.add(**fields)
    _daisy_show(cluster)

@utils.arg('cluster', metavar='<CLUSTER>', help='ID of cluster to modify.')
# @utils.arg('--name', metavar='<NAME>',
#            help='Name of host.')
# @utils.arg('--description', metavar='<DESCRIPTION>',
#            help='Description of host.')
# @utils.arg('--nodes', metavar='<NODES>',nargs='+',
#            help='id of cluster nodes to be updated.')
# @utils.arg('--networks', metavar='<NETWORKS>',nargs='+',
#            help='id of update networks.')
# @utils.arg('--floating_ranges', metavar='<FLOATING_RANGES>',nargs='+',
#            help='Cluster floating ranges:"172.16.0.130","172.16.0.254"')
# @utils.arg('--dns_nameservers', metavar='<DNS_NAMESERVERS>',nargs='+',
#            help='Cluster dns nameservers:"8.8.4.4" "8.8.8.8" ')
# @utils.arg('--net_l23_provider', metavar='<NET_123_PROVIDER>',
#            help='Cluster net_l23_provider.')
# @utils.arg('--base_mac', metavar='<BASE_MAC>',
#            help='Cluster base_mac.')
# @utils.arg('--internal_gateway', metavar='<INTERNAL_GATEWAY>',
#            help='Cluster internal gateway.')
# @utils.arg('--internal_cidr', metavar='<INTERNAL_CIDR>',
#            help='Cluster internal_cidr.')
# @utils.arg('--external_cidr', metavar='<EXTERNAL_CIDR>',
#            help='Cluster external cidr.')
# @utils.arg('--gre_id_range', metavar='<GRE_ID_RANGE>',nargs='+',
#            help='Cluster gre_id_range. 2 65535')
# @utils.arg('--vlan_range', metavar='<VLAN_RANGE>',nargs='+',
#            help='Cluster vlan_range:1000 1030')
# @utils.arg('--vni_range', metavar='<VNI_RANGE>',nargs='+',
#            help='Cluster vNI range:1000 1030')
# @utils.arg('--segmentation_type', metavar='<SEGMENTATION_TYPE>',
#            help='Cluster segmentation_type.')
# @utils.arg('--public_vip', metavar='<PUBLIC_VIP>',
#            help='Cluster public vip.')
@utils.arg('params_file_path', metavar='<PARAMS_FILE_PATH>',
           help="""Template file path.
                   Run \"daisy params-helper params_file_path\" for the template content.
                   Then save the output to a template file.Just use this path.""")
def do_cluster_update(gc, args):
    """Update a specific cluster."""
    # Filter out None values
    fields = None
    cluster = None
    if not args.params_file_path:
        if args.nodes:
            for arg_node in args.nodes:
                host = utils.find_resource(gc.hosts, arg_node)
                if host and host.deleted:
                    msg = "No host with an ID of '%s' exists." % host.id
                    raise exc.CommandError(msg)
        if args.networks:
            for arg_network in args.networks:
                network = utils.find_resource(gc.networks, arg_network)
                if network and network.deleted:
                    msg = "No network with an ID of '%s' exists." % network.id
                    raise exc.CommandError(msg)
        range_list = []
        if args.floating_ranges:
            for floating_ranges in args.floating_ranges:
                float_ip_list = floating_ranges.split(",")
                range_list.append(float_ip_list)
        args.floating_ranges = range_list
        fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

        cluster_arg = fields.pop('cluster')

        cluster = utils.find_resource(gc.clusters, cluster_arg)

        # Filter out values we can't use
        UPDATE_PARAMS = daisyclient.v1.clusters.UPDATE_PARAMS
        fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))
    else:
        cluster_arg = args.cluster
        cluster = utils.find_resource(gc.clusters, cluster_arg)
        fields = param_helper._read_template_file(args)

    cluster = gc.clusters.update(cluster, **fields)
    _daisy_show(cluster)

@utils.arg('subcommand_param', nargs='+',
           metavar='<SUBCOMMAND_PARAM>',
           help='Subcommand param, [\'params_file_path\', \'test\'].')
def do_params_helper(gc, args):
    """ Params helper for some subcommand. """
    PARAMS = ('params_file_path', 'test')
    valid_params_list = \
        [param for param in args.subcommand_param if param in PARAMS]

    for valid_param in valid_params_list:
        if 0 == cmp(valid_param, u"params_file_path"):
            print("------------------------------------------")
            print("Cluster \'name\' and \'description\' segment must be supportted.Template:")
            pprint.pprint(param_helper.CLUSTER_ADD_PARAMS_FILE)
            print("------------------------------------------")
        elif 0 == cmp(valid_param, u"test"):
            print("------------------------------------------")
            print("test")
            print("------------------------------------------")

@utils.arg('clusters', metavar='<CLUSTER>', nargs='+',
           help=' ID of cluster(s) to delete.')
def do_cluster_delete(gc, args):
    """Delete specified cluster(s)."""

    for args_cluster in args.clusters:
        cluster = utils.find_resource(gc.clusters, args_cluster)
        if cluster and cluster.deleted:
            msg = "No cluster with an ID of '%s' exists." % cluster.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting cluster delete for %s ...' %
                      encodeutils.safe_decode(args_cluster), end=' ')
            gc.clusters.delete(cluster)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete cluster %s' % (e, args_cluster))

@utils.arg('--name', metavar='<NAME>',
           help='Filter clusters to those that have this name.')
           
@utils.arg('--auto-scale', metavar='<AUTO_SCAELE>',
           help='auto-scale:1 or 0.')
@utils.arg('--page-size', metavar='<SIZE>', default=None, type=int,
           help='Number of clusters to request in each paginated request.')
@utils.arg('--sort-key', default='name',
           choices=daisyclient.v1.clusters.SORT_KEY_VALUES,
           help='Sort cluster list by specified field.')
@utils.arg('--sort-dir', default='asc',
           choices=daisyclient.v1.clusters.SORT_DIR_VALUES,
           help='Sort cluster list in specified direction.')
def do_cluster_list(gc, args):
    """List clusters you can access."""
    filter_keys = ['name','auto_scale']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])

    kwargs = {'filters': filters}
    if args.page_size is not None:
        kwargs['page_size'] = args.page_size

    kwargs['sort_key'] = args.sort_key
    kwargs['sort_dir'] = args.sort_dir

    clusters = gc.clusters.list(**kwargs)

    columns = ['ID', 'Name', 'Description', 'nodes', 'networks', 'Deleted']
    utils.print_list(clusters, columns)

@utils.arg('id', metavar='<ID>',
           help='Filter cluster to those that have this id.')
def do_cluster_detail(gc, args):
    """List cluster you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        cluster = utils.find_resource(gc.clusters, fields.pop('id'))
        _daisy_show(cluster)
    else:
        cluster = gc.clusters.list(**kwargs)
        columns = ['ID', 'Name','Description','nodes', 'networks', 'Deleted']
        utils.print_list(cluster, columns)    

#@utils.arg('cluster', metavar='<CLUSTER_ID>',
#           help='Filter results by an cluster ID.')
#def do_cluster_host_list(gc, args):
#    """Show cluster host membership by cluster or host."""
 #   if not args.cluster:
 #       utils.exit('Unable to list all members. Specify cluster-id')
 #   if args.cluster:
 #       kwargs = {'cluster': args.cluster}
#
 #   members = gc.cluster_hosts.list(**kwargs)
 #   columns = ['Cluster_ID', 'Host_ID']
 #   utils.print_list(members, columns)


@utils.arg('cluster', metavar='<CLUSTER>',
           help='Project from which to remove member.')
@utils.arg('node', metavar='<NODE>',
           help='id of host to remove as member.')
def do_cluster_host_del(gc, args):
    """Remove a host from cluster."""
    #cluster_id = utils.find_resource(gc.clusters, args.cluster).id
    #host_id = utils.find_resource(gc.hosts, args.node).id
    cluster_id = args.cluster
    host_id = args.node
    gc.cluster_hosts.delete(cluster_id, host_id)
    


@utils.arg('name', metavar='<NAME>',
           help='Component name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='Component description to be added.')
def do_component_add(gc, args):
    """Add a component."""
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.components.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    component = gc.components.add(**fields)

    _daisy_show(component)

@utils.arg('components', metavar='<COMPONENT>', nargs='+',
           help='ID of component(s) to delete.')
def do_component_delete(gc, args):
    """Delete specified component(s)."""

    for args_component in args.components:
        component = utils.find_resource(gc.components, args_component)
        if component and component.deleted:
            msg = "No component with an ID of '%s' exists." % component.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting component delete for %s ...' %
                      encodeutils.safe_decode(args_component), end=' ')
            gc.components.delete(component)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete component %s' % (e, args_component))

@utils.arg('--id', metavar='<ID>',
           help='Filter components to those that have this name.')
def do_component_list(gc, args):
    """List components you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        component = utils.find_resource(gc.components, fields.pop('id'))
        _daisy_show(component)
    else:
        components = gc.components.list(**kwargs)
        columns = ['ID', 'Name','Description', 'Deleted']
        utils.print_list(components, columns)

@utils.arg('component', metavar='<COMPONENT>', help='ID of component to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of component.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of component.')
def do_component_update(gc, args):
    """Update a specific component."""
    # Filter out None values
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    component_arg = fields.pop('component')
    component = utils.find_resource(gc.components, component_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.components.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    component = gc.components.update(component, **fields)
    _daisy_show(component)

@utils.arg('name', metavar='<NAME>',
           help='Service name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='Service description to be added.')
@utils.arg('--component-id', metavar='<COMPONENT_ID>',
           help='Services that belong to the component of the ID.')   
@utils.arg('--backup-type', metavar='<BACKUP_TYPE>',
           help='The backup-type mybe lb or ha.') 
def do_service_add(gc, args):
    """Add a service."""
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.services.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    service = gc.services.add(**fields)

    _daisy_show(service)

@utils.arg('services', metavar='<SERVICE>', nargs='+',
           help='ID of service(s) to delete.')
def do_service_delete(gc, args):
    """Delete specified service(s)."""

    for args_service in args.services:
        service = utils.find_resource(gc.services, args_service)
        if service and service.deleted:
            msg = "No service with an ID of '%s' exists." % service.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting service delete for %s ...' %
                      encodeutils.safe_decode(args_service), end=' ')
            gc.services.delete(service)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete service %s' % (e, args_service))

@utils.arg('--id', metavar='<ID>',
           help='Filter services to those that have this name.')
def do_service_list(gc, args):
    """List services you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        service = utils.find_resource(gc.services, fields.pop('id'))
        _daisy_show(service)
    else:
        services = gc.services.list(**kwargs)
        columns = ['ID', 'Name','Description', 'Component_ID', 'Backup_Type','Deleted']
        utils.print_list(services, columns)

@utils.arg('service', metavar='<SERVICE>', help='ID of service to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of service.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of service.')
@utils.arg('--component-id', metavar='<COMPONENT_ID>', 
           help='Services that belong to the component of the ID.')
@utils.arg('--backup-type', metavar='<BACKUP_TYPE>',
           help='The backup-type mybe lb or ha.') 
def do_service_update(gc, args):
    """Update a specific service."""
    # Filter out None values
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    service_arg = fields.pop('service')
    service = utils.find_resource(gc.services, service_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.services.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    service = gc.services.update(service, **fields)
    _daisy_show(service)

@utils.arg('name', metavar='<NAME>',
           help='Role name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='Role description to be added.')
#@utils.arg('--progress', metavar='<PROGRESS>',
#           help='The role of the progress.') 
@utils.arg('--config-set-id', metavar='<CONFIG_SET_ID>',
           help='Roles that belong to the config-set of the ID.')
@utils.arg('--nodes', metavar='<NODES>', nargs='+',
           help='Roles that belong to the host of the id,host id can be more than one')
@utils.arg('--services', metavar='<SERVICES>', nargs='+',
           help='Roles that belong to the service of the id, service id can be more than one')
#@utils.arg('--status', metavar='<STATUS>',
#           help='The role of the status.')
@utils.arg('--cluster-id', metavar='<CLUSTER_ID>',
           help='Roles that belong to cluster of id.')
@utils.arg('--type', metavar='<TYPE>',
           help='The value should be template or  custom.')
@utils.arg('--vip', metavar='<VIP>',
           help='float ip.')
@utils.arg('--glance-lv-size', metavar='<GLANCE_LV_SIZE>',
           help='the size of logic volume disk for storaging image, and the unit is M.')
@utils.arg('--deployment-backend', metavar='<deployment_backend>',
           help="deployment backend, supported bacends are 'tecs' and 'zenic' now.")
@utils.arg('--db-lv-size', metavar='<DB_LV_SIZE>',
           help='the size of database disk(M).')
@utils.arg('--nova-lv-size', metavar='<NOVA_LV_SIZE>',
           help='the size of logic volume disk for nvoa, and the unit is MB.')
def do_role_add(gc, args):
    """Add a role."""
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.roles.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    role = gc.roles.add(**fields)

    _daisy_show(role)

@utils.arg('roles', metavar='<ROLE>', nargs='+',
           help='ID of role(s) to delete.')
def do_role_delete(gc, args):
    """Delete specified role(s)."""

    for args_role in args.roles:
        role = utils.find_resource(gc.roles, args_role)
        if role and role.deleted:
            msg = "No role with an ID of '%s' exists." % role.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting role delete for %s ...' %
                      encodeutils.safe_decode(args_role), end=' ')
            gc.roles.delete(role)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete role %s' % (e, args_role))

@utils.arg('--cluster-id', metavar='<CLUSTER_ID>',
           help='Roles that belong to cluster of id.')
def do_role_list(gc, args):
    """List roles you can access."""
    filter_keys = ['cluster_id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}

    roles = gc.roles.list(**kwargs)
    columns = ['ID', 'Name','Description','Status','Progress','Config_Set_ID','CLUSTER_ID','TYPE','VIP','Deployment_Backend','Deleted']
    utils.print_list(roles, columns)

@utils.arg('id', metavar='<ID>',
           help='Filter roles to those that have this name.')
def do_role_detail(gc, args):
    """List roles you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        role = utils.find_resource(gc.roles, fields.pop('id'))
        _daisy_show(role)
    else:
        roles = gc.roles.list(**kwargs)
        columns = ['ID', 'Name','Description','Status','Progress','Config_Set_ID','CLUSTER_ID','TYPE','VIP','Deleted']
        utils.print_list(roles, columns)

@utils.arg('role', metavar='<ROLE>', help='ID of role to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of role.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of role.')
@utils.arg('--config-set-id', metavar='<CONFIG_SET_ID>', 
           help='Roles that belong to the config-set of the ID.')
@utils.arg('--nodes', metavar='<NODES>', nargs='+',
           help='Roles that belong to the host of the id,host id can be more than one')
@utils.arg('--services', metavar='<SERVICES>', nargs='+',
           help='Roles that belong to the service of the id, service id can be more than one')
#@utils.arg('--status', metavar='<STATUS>',
#           help='The role of the status.')  
#@utils.arg('--progress', metavar='<PROGRESS>',
#           help='The role of the progress.') 
@utils.arg('--cluster-id', metavar='<CLUSTER_ID>',
           help='Roles that belong to cluster of id.')
@utils.arg('--type', metavar='<TYPE>',
           help='The value should be template or  custom.')
@utils.arg('--vip', metavar='<VIP>',
           help='float ip.')
@utils.arg('--glance-lv-size', metavar='<GLANCE_LV_SIZE>',
           help='the size of logic volume disk for storaging image, and the unit is M.')
@utils.arg('--deployment-backend', metavar='<deployment_backend>',
           help="deployment backend, supported bacends are 'tecs' and 'zenic' now.")
@utils.arg('--db-lv-size', metavar='<DB_LV_SIZE>',
           help='the size of database disk(M).')
@utils.arg('--nova-lv-size', metavar='<NOVA_LV_SIZE>',
           help='the size of logic volume disk for nvoa, and the unit is MB.')
def do_role_update(gc, args):
    """Update a specific role."""
    # Filter out None values
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    role_arg = fields.pop('role')
    role = utils.find_resource(gc.roles, role_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.roles.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    role = gc.roles.update(role, **fields)
    _daisy_show(role)
	

@utils.arg('name', metavar='<NAME>',
           help='config_file name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='config_file description to be added.')
def do_config_file_add(gc, args):
    """Add a config_file."""
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.config_files.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    config_file = gc.config_files.add(**fields)

    _daisy_show(config_file)
    
@utils.arg('config_files', metavar='<CONFIG_FILE>', nargs='+',
           help='ID of config_file(s) to delete.')
def do_config_file_delete(gc, args):
    """Delete specified config_file(s)."""

    for args_config_file in args.config_files:
        config_file = utils.find_resource(gc.config_files, args_config_file)
        if config_file and config_file.deleted:
            msg = "No config_file with an ID of '%s' exists." % config_file.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting config_file delete for %s ...' %
                      encodeutils.safe_decode(args_config_file), end=' ')
            gc.config_files.delete(config_file)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete config_file %s' % (e, args_config_file))

@utils.arg('config_file', metavar='<CONFIG_FILE>', help='ID of config_file to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of config_file.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of config_file.')
def do_config_file_update(gc, args):
    """Update a specific config_file."""
    # Filter out None values
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    config_file_arg = fields.pop('config_file')
    config_file = utils.find_resource(gc.config_files, config_file_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.config_files.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    config_file = gc.config_files.update(config_file, **fields)
    _daisy_show(config_file)


def do_config_file_list(gc, args):
    """List config_files you can access."""
    filter_keys = ''
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config_file = utils.find_resource(gc.config_files, fields.pop('id'))
        _daisy_show(config_file)
    else:
        config_files = gc.config_files.list(**kwargs)
        columns = ['ID', 'Name','Description']
        utils.print_list(config_files, columns)	
		
@utils.arg('id', metavar='<ID>',
           help='Filter config_file to those that have this id.')
def do_config_file_detail(gc, args):
    """List config_files you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config_file = utils.find_resource(gc.config_files, fields.pop('id'))
        _daisy_show(config_file)
    else:
        config_files = gc.config_files.list(**kwargs)
        columns = ['ID', 'Name','Description']
        utils.print_list(config_files, columns)	
	
@utils.arg('name', metavar='<NAME>',
           help='config_set name to be added.')
@utils.arg('description', metavar='<DESCRIPTION>',
           help='config_set description to be added.')
def do_config_set_add(gc, args):
    """Add a config_set."""
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.config_sets.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    config_set = gc.config_sets.add(**fields)

    _daisy_show(config_set)
    
@utils.arg('config_sets', metavar='<CONFIG_SET>', nargs='+',
           help='ID of config_set(s) to delete.')
def do_config_set_delete(gc, args):
    """Delete specified config_set(s)."""

    for args_config_set in args.config_sets:
        config_set = utils.find_resource(gc.config_sets, args_config_set)
        if config_set and config_set.deleted:
            msg = "No config_set with an ID of '%s' exists." % config_set.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting config_set delete for %s ...' %
                      encodeutils.safe_decode(args_config_set), end=' ')
            gc.config_sets.delete(config_set)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete config_set %s' % (e, args_config_set))

@utils.arg('config_set', metavar='<CONFIG_SET>', help=' ID of config_set to modify.')
@utils.arg('--name', metavar='<NAME>',
           help='Name of config_set.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of config_set.')
def do_config_set_update(gc, args):
    """Update a specific config_set."""
    # Filter out None values
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    config_set_arg = fields.pop('config_set')
    config_set = utils.find_resource(gc.config_sets, config_set_arg)

    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.config_sets.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))

    config_set = gc.config_sets.update(config_set, **fields)
    _daisy_show(config_set)



def do_config_set_list(gc, args):
    """List config_sets you can access."""
    filter_keys = ''
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config_set = utils.find_resource(gc.config_sets, fields.pop('id'))
        _daisy_show(config_set)
    else:
        config_sets = gc.config_sets.list(**kwargs)
        columns = ['ID', 'Name','Description']
        utils.print_list(config_sets, columns)	

@utils.arg('id', metavar='<ID>',
           help='Filter components to those that have this name.')
def do_config_set_detail(gc, args):
    """List config_sets you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config_set = utils.find_resource(gc.config_sets, fields.pop('id'))
        _daisy_show(config_set)
    else:
        config_sets = gc.config_sets.list(**kwargs)
        columns = ['ID', 'Name','Description']
        utils.print_list(config_sets, columns)	

@utils.arg('config', metavar='<CONFIG>', nargs='+',
           help='ID of config(s) to delete.')
def do_config_delete(gc, args):
    """Delete specified config(s)."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.configs.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))
    gc.configs.delete(**fields)

def do_config_list(gc, args):
    """List configs you can access."""
    filter_keys = ''
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config = utils.find_resource(gc.configs, fields.pop('id'))
        _daisy_show(config)
    else:
        configs = gc.configs.list(**kwargs)
        columns = ['ID','SECTION' ,'KEY','Value','Description', 'Config_File_ID','config_version','running_version']
        utils.print_list(configs, columns)			

@utils.arg('id', metavar='<ID>',
           help='Filter configs to those that have this id.')
def do_config_detail(gc, args):
    """List configs you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        config = utils.find_resource(gc.configs, fields.pop('id'))
        _daisy_show(config)
    else:
        configs = gc.configs.list(**kwargs)
        columns = ['ID','SECTION' ,'KEY','Value','Description', 'Config_File_ID','config_version','running_version']
        utils.print_list(configs, columns)

@utils.arg('name', metavar='<NAME>', help='NAME of network.')
@utils.arg('description', metavar='<DESCRIPTION>', 
           help='Description of network.')
@utils.arg('network_type', metavar='<NETWORK_TYPE>' ,
           help='type of network:PUBLIC,PRIVATE,STORAGE,MANAGEMENT,EXTERNAL,DEPLOYMENT')
@utils.arg('--cluster-id', metavar='<CLUSTER>', help='ID of cluster, must be given.')
@utils.arg('--vlan-start', metavar='<VLAN_START>', 
           help='vlan start of network.for example: 10')
@utils.arg('--vlan-end', metavar='<VLAN_END>', 
           help='vlan end of network.for example: 80')             
@utils.arg('--cidr', metavar='<CIDR>', 
           help='vlan of network.')
@utils.arg('--ip', metavar='<IP>',
           help='network ip')
@utils.arg('--ip-ranges', metavar='<IP_RANGES>' ,nargs='+',
           help='ip ranges of network.  for example:"start":"172.16.0.2","end":"172.16.0.126"')
@utils.arg('--gateway', metavar='<GATEWAY>' ,
           help='gate way of network')		   
@utils.arg('--type', metavar='<TYPE>' ,
           help='type of network:custom or template')
@utils.arg('--ml2-type', metavar='<ML2_TYPE>' ,
           help='ml2 type:sriov , ovs or sriov,ovs')
@utils.arg('--physnet-name', metavar='<PHYSNET_NAME>' ,
           help='physnet name,eg:physnet_eth0')
@utils.arg('--capability', metavar='<CAPABILITY>' ,
           help='CAPABILITY of network:high or low')
@utils.arg('--vlan_id', metavar='<VLAN_ID>' ,
           help='Vlan Tag.')
@utils.arg('--mtu', metavar='<MTU>' ,
           help='Private plane mtu.eg.:1600.')
def do_network_add(gc, args):
    """Add a network."""
    ip_range_list = []
    if args.ip_ranges: 
        for ip_range in args.ip_ranges:
            ip_range_ref={}
            for range_value in ip_range.split(","):
                try:
                    k, v = range_value.split(":", 1)
                    if str(k) == "start":
                        ip_range_ref['start'] = str(v)
                    if str(k) == "end":
                        ip_range_ref['end'] = str(v)
                except ValueError: 
                        raise exc.CommandError("ip_ranges error")
            ip_range_list.append(ip_range_ref)
        args.ip_ranges = ip_range_list
    
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
 
    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.networks.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))

    network = gc.networks.add(**fields)

    _daisy_show(network)

@utils.arg('network', metavar='<NETWORK>', help='ID of network.')
@utils.arg('--network-type', metavar='<NETWORK_TYPE>' ,
           help='type of network:PUBLIC,PRIVATE,STORAGE,MANAGEMENT,EXTERNAL,DEPLOYMENT')
@utils.arg('--cluster-id', metavar='<CLUSTER>', help='ID of cluster .')
@utils.arg('--name', metavar='<NAME>',
           help='Name of network.')
@utils.arg('--description', metavar='<DESCRIPTION>', 
           help='Description of network.')
@utils.arg('--vlan-start', metavar='<VLAN_START>', 
           help='vlan start of network.for example: 10')
@utils.arg('--vlan-end', metavar='<VLAN_END>', 
           help='vlan end of network.for example: 80')             
@utils.arg('--cidr', metavar='<CIDR>', 
           help='vlan of network.') 
@utils.arg('--ip-ranges', metavar='<IP_RANGES>' ,nargs='+',
           help='ip ranges of network,for example:"start":"172.16.0.2","end":"172.16.0.126"') 
@utils.arg('--gateway', metavar='<GATEWAY>' ,
           help='gate way of network')		   
@utils.arg('--type', metavar='<TYPE>' ,
           help='type of network:custom or template')
@utils.arg('--ml2-type', metavar='<ML2_TYPE>' ,
           help='ml2 type:sriov , ovs or sriov,ovs')
@utils.arg('--physnet-name', metavar='<PHYSNET_NAME>' ,
           help='physnet name,eg:physnet_eth0')
@utils.arg('--capability', metavar='<CAPABILITY>' ,
           help='CAPABILITY of network:high or low')
@utils.arg('--vlan_id', metavar='<VLAN_ID>' ,
           help='Vlan Tag.')
@utils.arg('--mtu', metavar='<MTU>' ,
           help='Private plane mtu.eg.:1600.')
def do_network_update(gc, args):
    """Update a specific network."""
    # Filter out None values
    
    ip_range_list = []

    if args.ip_ranges: 
        for ip_range in args.ip_ranges:
            ip_range_ref={}
            for range_value in ip_range.split(","):
                try:
                    k, v = range_value.split(":", 1)
                    if str(k) == "start":
                        ip_range_ref['start'] = str(v)
                    if str(k) == "end":
                        ip_range_ref['end'] = str(v)
                except ValueError: 
                        raise exc.CommandError("ip_ranges error")
            ip_range_list.append(ip_range_ref)
        args.ip_ranges = ip_range_list
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    network_arg = fields.pop('network')

    network = utils.find_resource(gc.networks, network_arg)
    # Filter out values we can't use
    UPDATE_PARAMS = daisyclient.v1.networks.UPDATE_PARAMS
    fields = dict(filter(lambda x: x[0] in UPDATE_PARAMS, fields.items()))
    

    network = gc.networks.update(network, **fields)
    _daisy_show(network)
    

@utils.arg('networks', metavar='<NETWORK>', nargs='+', help='ID of network.')
@utils.arg('--cluster-id', metavar='<CLUSTER>', help='ID of cluster .')    
def do_network_delete(gc, args):
    """Delete specified network(s)."""

    for args_network in args.networks:
        network = utils.find_resource(gc.networks, args_network)
        if network and network.deleted:
            msg = "No network with an ID of '%s' exists." % network.id
            raise exc.CommandError(msg)
        try:
            if args.verbose:
                print('Requesting network delete for %s ...' %
                      encodeutils.safe_decode(args_network), end=' ')
            gc.networks.delete(network)

            if args.verbose:
                print('[Done]')

        except exc.HTTPException as e:
            if args.verbose:
                print('[Fail]')
            print('%s: Unable to delete network %s' % (e, args_network))

@utils.arg('ID', metavar='<cluster ID>',
           help='Filter networks to those that have this name.')
@utils.arg('--page-size', metavar='<SIZE>', default=None, type=int,
           help='Number of networks to request in each paginated request.')
@utils.arg('--sort-key', default='name',
           choices=daisyclient.v1.networks.SORT_KEY_VALUES,
           help='Sort networks list by specified field.')
@utils.arg('--sort-dir', default='asc',
           choices=daisyclient.v1.networks.SORT_DIR_VALUES,
           help='Sort networks list in specified direction.')
def do_network_list(gc, args):
    """List networks you can access."""
    filter_keys = ['ID']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    kwargs = {'id': args.ID}
    kwargs = {'filters': filters}
    if args.page_size is not None:
        kwargs['page_size'] = args.page_size

    kwargs['sort_key'] = args.sort_key
    kwargs['sort_dir'] = args.sort_dir

    networks = gc.networks.list(**kwargs)
    
    columns = ['ID', 'Name', 'Cluster_id', 'Description', 'Deleted', 'vlan_start','vlan_end','gateway','cidr','type','updated_at', 'deleted_at','created_at','ip_ranges']
    utils.print_list(networks, columns)


@utils.arg('id', metavar='<ID>',
           help='Filter network to those that have this id.')
def do_network_detail(gc, args):
    """List network you can access."""
    filter_keys = ['id']
    filter_items = [(key, getattr(args, key)) for key in filter_keys]
    filters = dict([item for item in filter_items if item[1] is not None])
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    kwargs = {'filters': filters}
    if filters:
        network = utils.find_resource(gc.networks, fields.pop('id'))
        _daisy_show(network)
    else:
        network = gc.networks.list(**kwargs)
        columns = ['ID', 'Name', 'Cluster_id', 'Description', 'Deleted', 'vlan_start','vlan_end','gateway','cidr','type','updated_at', 'deleted_at','created_at','ip_ranges']
        utils.print_list(network, columns)        


@utils.arg('cluster_id', metavar='<CLUSTER>', 
            help='ID of cluster to install TECS.')
@utils.arg('--version-id', metavar='<VERSION>',
           help='Version of TECS.')
@utils.arg('--deployment-interface', metavar='<DEPLOYMNET>',
           help='Network interface construction of PXE server(eg:eth0).')
def do_install(dc, args):
    """Install TECS."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.install.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    install = dc.install.install(**fields)

    _daisy_show(install)


@utils.arg('cluster_id', metavar='<CLUSTER_ID>', 
            help='The cluster ID to uninstall TECS.')
def do_uninstall(gc, args):
    """Uninstall TECS."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.uninstall.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    uninstall = gc.uninstall.uninstall(**fields)

@utils.arg('cluster_id', metavar='<CLUSTER_ID>', 
            help='The cluster ID to query progress of uninstall TECS .')
def do_query_uninstall_progress(gc, args):
    """Query uninstall progress."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    CREATE_PARAMS = daisyclient.v1.uninstall.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    query_progress = gc.uninstall.query_progress(**fields)

    _daisy_show(query_progress)


@utils.arg('cluster_id', metavar='<CLUSTER_ID>', 
            help='The cluster ID to update TECS.')
def do_update(gc, args):
    """update TECS."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.update.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    update = gc.update.update(**fields)

@utils.arg('cluster_id', metavar='<CLUSTER_ID>', 
            help='The cluster ID to query progress of update TECS .')
def do_query_update_progress(gc, args):
    """Query update progress."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    CREATE_PARAMS = daisyclient.v1.update.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    query_progress = gc.update.query_progress(**fields)
    _daisy_show(query_progress)  

@utils.arg('cluster_id', metavar='<CLUSTER_ID>', 
            help='The cluster ID on which to export tecs and HA config file from database.')
def do_export_db(gc, args):
    """export database."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))

    # Filter out values we can't use
    CREATE_PARAMS = daisyclient.v1.install.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    
    config_file = gc.install.export_db(**fields)
    _daisy_show(config_file)
    

@utils.arg('--cluster', metavar='<CLUSTER>', 
            help='ID of cluster to config file.')
@utils.arg('--role', metavar='<ROLE_NAME>',
           help=' role name.')
@utils.arg('--config-set', metavar='<config_set>',
           help='id of the config-set.')
@utils.arg('--config', metavar='<file-name=name,section=section,key=key,value=value,description=description>',
           nargs='+',
           help='file-name must take full path.such as:file-name=/etc/nova/nova.conf,section=DEFAULT,key=port,value=5661,description=description')
def do_config_add(gc, args):
    """add and update config interfaces."""
    config_interface_list = []
    if args.config: 
        for interfaces in args.config:
            interface_info = {"file-name":"", "section":"", "key":"", "value": "","description": ""}
            for kv_str in interfaces.split(","):                                
                try:                                        
                    k, v = kv_str.split("=", 1)
                except ValueError:                                        
                    raise exc.CommandError("config-interface error")
                if k in interface_info:
                    interface_info[k] = v
            config_interface_list.append(interface_info)
        args.config = config_interface_list
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    CREATE_PARAMS = daisyclient.v1.configs.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    config_interface_info = gc.configs.add(**fields)
    _daisy_show(config_interface_info)
    
@utils.arg('cluster', metavar='<CLUSTER>', 
            help='ID of cluster to config file.')
@utils.arg('--role', metavar='<NAME>',
           nargs='+',
           help=' role name.')
def do_cluster_config_set_update(gc, args):
    """the cluster of config effect."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    CREATE_PARAMS = daisyclient.v1.configs.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    config_interface_info = gc.config_sets.cluster_config_set_update(**fields)
    _daisy_show(config_interface_info)
    
@utils.arg('cluster', metavar='<CLUSTER>', 
            help='ID of cluster to config file.')
@utils.arg('--role', metavar='<NAME>',
           nargs='+',
           help=' role name.')
def do_cluster_config_set_progress(gc, args):
    """query cluster of config progress."""
    fields = dict(filter(lambda x: x[1] is not None, vars(args).items()))
    CREATE_PARAMS = daisyclient.v1.configs.CREATE_PARAMS
    fields = dict(filter(lambda x: x[0] in CREATE_PARAMS, fields.items()))
    config_set_progress = gc.config_sets.cluster_config_set_progress(**fields)
    _daisy_show(config_set_progress)
