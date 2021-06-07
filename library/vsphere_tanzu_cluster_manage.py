#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vmware_namespace_cluster_vds_manager
short_description: Enable, disable and update workload management on a vSphere cluster
description:
- Configure workload management on a vSphere cluster
author:
- Matt Proud (@laidbackware)
notes:
- Tested on vSphere 7.0u2
requirements:
- python >= 3.5
- PyVmomi
- vSphere Automation SDK
- Ansible Community VMware collection
options:
hostname: '{{ vcenter_hostname }}'
    cluster_distributed_switch:
        escription:
        - The name of the vSphere distributed switch for use with NSX-T.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(NSXT_CONTAINER_PLUGIN).
        type: str
        required: False
    cluster_name: 
        description:
        - The name of the name of the vsphere cluster to configure.
        type: str
        required: True
    default_content_library: 
        description:
        - The name of the content library hosting VM images.
        required: False
    dns_search_domains: 
        description:
        - The dns search domain to assign to the management cluster.
        type: str
        required: False
    cluster_distributed_switch:
        description:
        - The name of the vSphere distributed switch for use with NSX-T.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(NSXT_CONTAINER_PLUGIN).
        type: str
        required: False
    egress_cidrs:
        description:
        - List of strings containing CIDRs to be used by NSX-T for egress traffic.
        - Each item should follow network CIDR notation e.g 10.0.0.0/24.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(NSXT_CONTAINER_PLUGIN).
        type: list
        required: False
    ephemeral_storage_policy:
        description:
        - The VM Storage Policy name to be used for ephemeral storage.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    haproxy_ca_chain:
        description:
        - Haproxy management CA certificate.
        - Can either be public key of a self signed cert or the signing CA public key.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    haproxy_management_ip:
        description:
        - Haproxy management IP address.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    haproxy_management_port:
        description:
        - Haproxy management TCP port.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        default: 5556
        required: False
    haproxy_password:
        description:
        - Haproxy API password.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    haproxy_username:
        description:
        - Haproxy API username.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    haproxy_ip_range_list:
        description:
        - List of IP ranges used by haproxy for load balancers.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        suboptions:
            starting_ip:
                type: str
                description: First usable IP address.
            num_of_ips:
                type: int
                description: Number of sequential IPs to use after starting_IP.
        type: list
        elements: dict
        required: False
    image_storage_policy:
        description:
        - The VM Storage Policy name to be used for image storage.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    ingress_cidrs:
        description:
        - List of strings containing CIDRs to be used by NSX-T for ingress traffic.
        - Each item should follow network CIDR notation e.g 10.0.0.0/24
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(NSXT_CONTAINER_PLUGIN).
        type: list
        required: False
    management_address_count:
        description:
        - The default number of addresses reserved for management VMs.
        - This is required only if I(state) is set to C(present).
        type: int
        required: False
    management_dns_servers:
        description:
        - List of strings containing DNS server IPs for the management network.
        - This is required only if I(state) is set to C(present).
        type: list
        required: False
    management_gateway:
        description:
        - The default gateway used by the management VMs.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    management_netmask:
        description:
        - The netmask used by the management VMs.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    management_ntp_servers:
        description:
        - List of strings containing NTP server IPs used by the management network.
        - This is required only if I(state) is set to C(present).
        type: list
        required: False
    management_port_group: 
        description:
        - The port group used by the management VMs.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    management_starting_address:
        description:
        - The starting IP to be used by the management VMs.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    master_storage_policy:
        description:
        - The VM Storage Policy name to be used for supervisor VMs.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    network_provider:
        description:
        - The network provider to be used in the supervisor cluster.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
        choices: [ 'VSPHERE_NETWORK', 'NSXT_CONTAINER_PLUGIN' ]
    pod_cidrs:
        description:
        - List of strings containing CIDRs to be used by NSX-T for pod assignment.
        - Each item should follow network CIDR notation e.g 10.0.0.0/24
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(NSXT_CONTAINER_PLUGIN).
        type: list
        required: False
    workload_dns_servers:
        description:
        - List of strings containing DNS server IPs for the workload network.
        - This is required only if I(state) is set to C(present).
        type: list
        required: True
    workload_gateway:
        description:
        - The default gateway used by the workload VMs.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    workload_netmask:
        description:
        - The netmask used by the workload VMs.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    workload_ntp_servers:
        description:
        - List of strings containing NTP server IPs used by the workload network.
        - This is required only if I(state) is set to C(present).
        type: list
        required: False
    workload_portgroup:
        description:
        - The port group used by the workload VMs.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        type: str
        required: False
    workload_ip_range_list:
        description:
        - List of IP ranges used by workload VMs.
        - This is required only if I(state) is set to C(present).
        - This is required only if I(network_provider) is set to C(VSPHERE_NETWORK).
        suboptions:
            starting_ip:
                type: str
                description: First usable IP address.
            num_of_ips:
                type: int
                description: Number of sequential IPs to use after starting_IP.
        type: list
        elements: dict
        required: False
    services_cidr:
        description:
        - The cidr to be used by internal Kubernetes services.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
    supervisor_size:
        description:
        - The network provide to be used in the supervisor cluster.
        - This is required only if I(state) is set to C(present).
        type: str
        required: False
        choices: [ 'TINY', 'SMALL', 'MEDIUM', 'LARGE']
    
extends_documentation_fragment:
- community.vmware.vmware_rest_client.documentation

'''
EXAMPLES = r'''
- name: Enable Namespaces on a Cluster with vSphere Networking
  vsphere_tanzu_cluster_manage:
    hostname: vcenter.example.local
    username: administrator@vsphere.local
    password: password
    validate_certs: false
    cluster_name: tkgs-cluster
    default_content_library: tkgs-library
    dns_search_domains: 
        -   example.local
    ephemeral_storage_policy: tkgs-storage-policy
    haproxy_ca_chain: |
        -----BEGIN CERTIFICATE-----
        <Public key>
        -----END CERTIFICATE-----
    haproxy_management_ip: "10.0.0.2"
    haproxy_management_port: "5556"
    haproxy_password: password
    haproxy_username: haproxy
    haproxy_ip_range_list:
        -   starting_ip: "172.31.0.1"
            num_of_ips: 30
    image_storage_policy: tkgs-storage-policy
    management_address_count: 5
    management_dns_servers: 
        -   "192.168.0.1"
    management_gateway: "10.0.0.1"
    management_port_group: routed-pg
    management_netmask: "255.255.255.0"
    management_ntp_servers: 
        -   "192.168.0.1"
    management_starting_address: "10.0.0.3"
    master_storage_policy: tkgs-storage-policy
    network_provider: VSPHERE_NETWORK  
    workload_dns_servers:
        -   "192.168.0.1" 
    workload_gateway: "172.31.0.1"
    workload_netmask: "255.255.255.0"
    workload_ntp_servers: 
        -   "192.168.0.1"
    workload_portgroup: private-pg
    workload_ip_range_list:
        -   starting_ip: "172.31.0.3"
            num_of_ips: 120
    services_cidr: "10.255.252.0/22"
    supervisor_size: TINY
    state: present
  delegate_to: localhost
  async: 1800
  poll: 5

- name: Enable Namespaces on a Cluster with NSX-T
  vsphere_tanzu_cluster_manage:
    hostname: vcenter.example.local
    username: administrator@vsphere.local
    password: password
    validate_certs: false
    cluster_distributed_switch: vds-nsxt
    cluster_name: tkgs-cluster
    default_content_library: tkgs-library
    dns_search_domains:
        -   example.local
    egress_cidrs: 10.0.1.0/24
    ephemeral_storage_policy: tkgs-storage-policy
    image_storage_policy: tkgs-storage-policy
    ingress_cidrs: 10.0.0.0/24
    management_address_count: 5
    management_dns_servers: 
        -   "192.168.0.1"
    management_gateway: "10.0.0.1"
    management_port_group: routed-pg
    management_netmask: "255.255.255.0"
    management_ntp_servers: 
        -   "192.168.0.1"
    management_starting_address: "10.0.0.3"
    master_storage_policy: tkgs-storage-policy
    network_provider: NSXT_CONTAINER_PLUGIN
    nsx_edge_cluster: edge-cluster-1
    pod_cidrs: 172.16.0.0/20
    workload_dns_servers:
        -   "192.168.0.1" 
    workload_ntp_servers: 
        -   "192.168.0.1"
    services_cidr: "10.255.252.0/22"
    supervisor_size: TINY
    state: present
  delegate_to: localhost
  async: 1800
  poll: 5

- name: Disable Namespaces on Cluster
  vsphere_tanzu_cluster_manage:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    cluster_name: tkgs-cluster
    state: absent
  delegate_to: localhost
'''

RETURN = r'''
namespace_cluster_vds_info:

'''

try:
    from pyVmomi import vim
except ImportError:
    pass

import uuid, ipaddress
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.vmware.plugins.module_utils.vmware_rest_client import VmwareRestClient
from ansible_collections.community.vmware.plugins.module_utils.vmware import PyVmomi, find_object_by_name
import urllib3
urllib3.disable_warnings()

HAS_VAUTOMATION_PYTHON_SDK = False
try:
    from com.vmware.vcenter.namespace_management_client import Clusters, LoadBalancers, Ipv4Cidr, Networks, IPRange, DistributedSwitchCompatibility, EdgeClusterCompatibility
    HAS_VAUTOMATION_PYTHON_SDK = True
except ImportError:
    pass


class LegacyObjectModel(PyVmomi):
    def __init__(self, module):
        super(LegacyObjectModel, self).__init__(module)
    
    def get_dist_switch_by_name(self, switch_name):
        switch_objs = find_object_by_name(self.content, switch_name, vim.DistributedVirtualSwitch, None)
        if switch_objs:
            return switch_objs.uuid
        else:
            self.module.fail_json(msg="Distributed Switch with name [%s] not found" % switch_name)
        

class VmwareNamespaceClusterVdsManage(VmwareRestClient):
    def __init__(self, module):
        """Constructor."""
        super(VmwareNamespaceClusterVdsManage, self).__init__(module)

        self.cluster_object = Clusters(self.api_client._stub_config)
        self.loadbalancer_object = LoadBalancers(self.api_client._stub_config)
        self.network_object = Networks(self.api_client._stub_config)
        self.vsphere_api_object_mapping = {
            'network': self.api_client.vcenter.Network,
            'cluster': self.api_client.vcenter.Cluster,
            'policy': self.api_client.vcenter.storage.Policies
        }
        self.cluster_distributed_switch = self.params.get('cluster_distributed_switch')
        self.cluster_name = self.params.get('cluster_name')
        self.cluster_id = self.get_object_by_name(self.cluster_name, 'cluster')
        self.default_content_library = self.params.get('default_content_library')
        self.dns_search_domains = self.params.get('dns_search_domains')
        self.egress_cidrs = self.params.get('egress_cidrs')
        self.ephemeral_storage_policy = self.params.get('ephemeral_storage_policy')
        self.haproxy_ca_chain = self.params.get('haproxy_ca_chain')
        self.haproxy_management_ip = self.params.get('haproxy_management_ip')
        self.haproxy_management_port = self.params.get('haproxy_management_port')
        self.haproxy_password = self.params.get('haproxy_password')
        self.haproxy_ip_range_list = self.params.get('haproxy_ip_range_list')
        self.haproxy_username = self.params.get('haproxy_username')
        self.image_storage_policy = self.params.get('image_storage_policy')
        self.ingress_cidrs = self.params.get('ingress_cidrs')
        self.network_provider = self.params.get('network_provider')
        self.management_address_count = self.params.get('management_address_count')
        self.management_dns_servers = self.params.get('management_dns_servers')
        self.management_netmask = self.params.get('management_netmask')
        self.management_ntp_servers = self.params.get('management_ntp_servers')
        self.management_gateway = self.params.get('management_gateway')
        self.management_port_group = self.params.get('management_port_group')
        self.management_starting_address = self.params.get('management_starting_address')
        self.master_storage_policy = self.params.get('master_storage_policy')
        self.nsx_edge_cluster = self.params.get('nsx_edge_cluster')
        self.pod_cidrs = self.params.get('pod_cidrs')
        self.services_cidr = self.params.get('services_cidr')
        self.supervisor_size = self.params.get('supervisor_size')
        self.workload_dns_servers = self.params.get('workload_dns_servers')
        self.workload_gateway = self.params.get('workload_gateway')
        self.workload_netmask = self.params.get('workload_netmask')
        self.workload_ntp_servers = self.params.get('workload_ntp_servers')
        self.workload_portgroup = self.params.get('workload_portgroup')
        self.workload_ip_range_list = self.params.get('workload_ip_range_list') 

    def process_state(self):
        """
        Manage states of Cluster Enablement
        """
        self.desired_state = self.params.get('state')
        namespace_cluster_states = {
            'absent': {
                'present': self.state_disable_cluster,
                'absent': self.state_exit_unchanged,
            },
            'present': {
                'present': self.state_update_cluster,
                'absent': self.state_enable_cluster,
            }
        }
        namespace_cluster_states[self.desired_state][self.check_namespace_cluster_status(self.desired_state)]()

    def check_namespace_cluster_status(self, desired_state):
        """
        Check if Workload Management is enabled for a specific cluster
        Returns: 'present' if workload management is enabled or configured, else 'absent'
        """
        try:
            existing_cluster_status = self.cluster_object.get(self.cluster_id).config_status
            if existing_cluster_status == 'RUNNING' or existing_cluster_status == 'ERROR':
                return 'present'
            elif existing_cluster_status == 'CONFIGURING' and desired_state == 'absent':
                return 'present'
            else:
                self.module.fail_json(msg="Operation cannot continue. Cluster [%s] is currently in state %s" % (self.cluster_id, existing_cluster_status))
        except Exception:
            return 'absent'

    def state_exit_unchanged(self):
        """
        Return unchanged state

        """
        self.module.exit_json(changed=False)

    # Checks if a CIDR is valid
    def check_ip_address(self, address, purpose, address_type):
        try:
            ipaddress.ip_network(address)
        except ValueError:
            self.module.fail_json(msg="%s %s %s is invalid" % (purpose, address_type, address))

    # Takes a list of cidr strings and return a list of IPRange objects
    def build_range_list(self, ip_range_list, purpose):
        output_ip_ranges = []
        for ip_range in ip_range_list:
            try:
                self.check_ip_address(ip_range['starting_ip'], purpose, 'ip address')
                output_ip_ranges.append(IPRange(address=ip_range['starting_ip'], 
                                            count=int(ip_range['num_of_ips'])))
            except (KeyError, AttributeError) as f:
                self.module.fail_json(msg="%s does not have the required fields. Error: %s" % (purpose, str(f)))
        return output_ip_ranges

    # Takes a list of cidr strings and return a list of IPRange objects
    def build_cidr_list(self, cidr_list, purpose):
        output_cidr_list = []
        for cidr in cidr_list:
            try:
                self.check_ip_address(cidr, purpose, 'cidr')
                output_cidr_list.append(
                    Ipv4Cidr(address=cidr.split('/')[0], prefix=int(cidr.split('/')[1]))
                )
            except (KeyError, AttributeError) as f:
                self.module.fail_json(msg="%s does not have the required fields. Error: %s" % (purpose, str(f)))
        return output_cidr_list

    # Gets the internal identifier of an object
    def get_object_by_name(self, object_name, object_type):
        object_list = self.vsphere_api_object_mapping[object_type].list()
        for item in object_list:
            if item.name == object_name:
                object_id = eval("item.%s" % object_type)
                return object_id
        self.module.fail_json(msg="%s named %s was not found" % (object_type, object_name))

    # Gets the internal identifier of an object
    def get_content_library_by_name(self, library_name):
        library_list = self.api_client.content.SubscribedLibrary.list()
        for library_id in library_list:
            library_object = self.api_client.content.SubscribedLibrary.get(library_id)
            if library_object.name == library_name:
                return library_id
        self.module.fail_json(msg="Content library named %s was not found" % library_name)

    def validate_distributed_switch(self, distributed_switch_uid):
        compatible_switches = DistributedSwitchCompatibility(self.api_client._stub_config).list(self.cluster_id)
        if not any(ds.distributed_switch == distributed_switch_uid for ds in compatible_switches):
            self.module.fail_json(
                msg="Distributed switch %s exists but is not supported with cluster %s" %
                    (self.cluster_distributed_switch, self.cluster_name)
            )

    def get_nsxt_edge_by_name(self, distributed_switch_uid):
        compatible_edge_clusters = EdgeClusterCompatibility(self.api_client._stub_config).list(
            self.cluster_id, distributed_switch_uid
        )
        for edge_cluster in compatible_edge_clusters:
            if edge_cluster.display_name == self.nsx_edge_cluster:
                return edge_cluster.edge_cluster
        self.module.fail_json(
            msg="NSX-T Edge Cluster %s is not supported with cluster %s" %
                (self.nsx_edge_cluster, self.cluster_name)
        )

    def enable_cluster(self, cluster_spec):
        self.cluster_object.enable(self.cluster_id, cluster_spec)

        error_count = 0
        errors_to_tollerate = 48
        # Wait until workload management reports as configured
        while True:
            cluster_object = self.cluster_object.get(self.cluster_id)
            cluster_status = cluster_object.config_status
            
            if cluster_status == 'RUNNING':
                break
            elif cluster_status == 'ERROR':
                # Tollerate errors as it seems to randomly enter error states and then recover
                error_count += 1
                if error_count > errors_to_tollerate:
                    cluster_messages = cluster_object.messages
                    self.module.fail_json(
                        msg="Enabling workload management on [%s] failed, status [%s] with error %s" % 
                            (self.cluster_name, cluster_status, cluster_messages)
                    )
            sleep(5)
        
        failed = False
        error_count = 0
        # Wait until Kubernetes reports as running
        while True:
            cluster_object = self.cluster_object.get(self.cluster_id)
            kubernetes_status = cluster_object.kubernetes_status
            
            if kubernetes_status == 'READY':
                break
            elif kubernetes_status == 'ERROR' or kubernetes_status == 'WARNING':
                # Tollerate errors as it seems to randomly enter error states and then recover
                error_count += 1
                if error_count > errors_to_tollerate:
                    failed = False
                    break
            else:
                failed = False
                break
            sleep(5)

        if failed:
            kubernetes_status_messages = cluster_object.kubernetes_status_messages
            self.module.fail_json(
                msg="Kubernetes failed to run on [%s] failed, status [%s] with error: %s" % (self.cluster_name, kubernetes_status, kubernetes_status_messages)
            )

    def state_enable_cluster(self):
        """
        Enable workload management on a cluster using vSphere networking.
        """

        cluster_spec = self.cluster_object.EnableSpec()
        cluster_spec.size_hint = self.supervisor_size
        cluster_spec.network_provider = self.network_provider
        cluster_spec.master_dns = self.management_dns_servers
        cluster_spec.worker_dns = self.workload_dns_servers
        cluster_spec.master_ntp_servers = self.management_ntp_servers
        if self.dns_search_domains:
            cluster_spec.master_dns_search_domains = self.dns_search_domains
        
        cluster_spec.image_storage = self.cluster_object.ImageStorageSpec(
            self.get_object_by_name(self.image_storage_policy, 'policy')
        )
        cluster_spec.ephemeral_storage_policy = self.get_object_by_name(self.ephemeral_storage_policy, 'policy')
        cluster_spec.master_storage_policy = self.get_object_by_name(self.master_storage_policy, 'policy')

        if self.default_content_library:
            default_content_library = self.get_content_library_by_name(self.default_content_library)
            cluster_spec.default_kubernetes_service_content_library = default_content_library

        management_network_range = self.cluster_object.Ipv4Range()
        management_network_range.starting_address = self.management_starting_address
        management_network_range.address_count = self.management_address_count
        management_network_range.subnet_mask = self.management_netmask
        management_network_range.gateway = self.management_gateway

        management_network_spec = self.cluster_object.NetworkSpec()
        management_network_spec.network = self.get_object_by_name(self.management_port_group, 'network')
        management_network_spec.mode = 'STATICRANGE'
        management_network_spec.address_range = management_network_range
        
        cluster_spec.master_management_network = management_network_spec
        
        self.check_ip_address(self.services_cidr, 'services_cidr', 'cidr')
        services_cidr = Ipv4Cidr(
            address=self.services_cidr.split('/')[0], prefix=int(self.services_cidr.split('/')[1])
        )
        cluster_spec.service_cidr = services_cidr

        if self.network_provider == 'VSPHERE_NETWORK':
            #TODO check HA proxy connection and error if issues
            haproxy_spec = self.loadbalancer_object.HAProxyConfigCreateSpec()
            haproxy_spec.servers = [self.loadbalancer_object.Server(host=self.haproxy_management_ip ,port=int(self.haproxy_management_port))]
            haproxy_spec.username = self.haproxy_username
            haproxy_spec.password = self.haproxy_password
            haproxy_spec.certificate_authority_chain = self.haproxy_ca_chain

            loadbalancer_spec = self.loadbalancer_object.ConfigSpec()
            loadbalancer_spec.id = 'haproxy'
            haproxy_ranges = self.build_range_list(self.haproxy_ip_range_list, 'haproxy_ip_range_list')
            loadbalancer_spec.address_ranges = haproxy_ranges
            loadbalancer_spec.provider = 'HA_PROXY'
            loadbalancer_spec.ha_proxy_config_create_spec = haproxy_spec
        
            workload_vsphere_network_spec = self.network_object.VsphereDVPGNetworkCreateSpec()
            workload_vsphere_network_spec.portgroup = self.get_object_by_name(self.workload_portgroup, 'network')
            workload_ranges = self.build_range_list(self.workload_ip_range_list, 'workload_ip_range_list')
            workload_vsphere_network_spec.address_ranges = workload_ranges
            workload_vsphere_network_spec.gateway = self.workload_gateway
            workload_vsphere_network_spec.subnet_mask = self.workload_netmask

            workload_network_spec = self.network_object.CreateSpec()
            workload_network_spec.network = 'network-1'
            workload_network_spec.network_provider = self.cluster_object.NetworkProvider.VSPHERE_NETWORK
            workload_network_spec.vsphere_network = workload_vsphere_network_spec

            workload_network_enable_spec = self.cluster_object.WorkloadNetworksEnableSpec()
            workload_network_enable_spec.supervisor_primary_workload_network = workload_network_spec
        
            cluster_spec.workload_networks_spec = workload_network_enable_spec
            cluster_spec.workload_ntp_servers = self.workload_ntp_servers
            cluster_spec.load_balancer_config_spec = loadbalancer_spec

        elif self.network_provider == 'NSXT_CONTAINER_PLUGIN':
            nsx_spec = self.cluster_object.NCPClusterNetworkEnableSpec()
            nsx_spec.egress_cidrs = self.build_cidr_list(self.egress_cidrs, 'egress cidrs')
            nsx_spec.ingress_cidrs = self.build_cidr_list(self.ingress_cidrs, 'ingress cidrs')
            nsx_spec.pod_cidrs = self.build_cidr_list(self.pod_cidrs, 'pod cidrs')
            distributed_switch_uid = LegacyObjectModel(self.module).get_dist_switch_by_name(self.cluster_distributed_switch)
            self.validate_distributed_switch(distributed_switch_uid)
            nsx_spec.cluster_distributed_switch = distributed_switch_uid
            nsx_spec.nsx_edge_cluster = self.get_nsxt_edge_by_name(distributed_switch_uid)
            cluster_spec.ncp_cluster_network_spec = nsx_spec
        
        if self.module.check_mode:
            action = "would have been enabled"
        else:
            self.enable_cluster(cluster_spec)
            action = 'enabled'
        
        self.module.exit_json(
            changed=True,
            namespace_cluster_results = dict(
                msg="Cluster '%s' %s for workload management" % (self.cluster_name, action),
                cluster_name=self.cluster_name,
                cluster_id=self.cluster_id,
                cluster_state='RUNNING'
            )
        )

    def state_update_cluster(self):
        self.module.exit_json(
            changed=False,
            namespace_cluster_vds_info = dict(msg='Updates not currently supported')
        )

    def state_disable_cluster(self):
        """
        Disable cluser

        """
        self.cluster_object.disable(self.cluster_id)
        self.module.exit_json(
            changed=True,
            namespace_cluster_results=dict(
            msg="Cluster '%s' has had workload management enabled." % self.cluster_name,
                cluster_name=self.cluster_name,
                cluster_id=self.cluster_id,
            )
        )


def main():
    argument_spec = VmwareRestClient.vmware_client_argument_spec()
    argument_spec.update(
        
        cluster_distributed_switch=dict(type='str', required=False),
        cluster_name=dict(type='str', required=True),
        default_content_library=dict(type='str', required=False),
        dns_search_domains=dict(type='list', required=False),
        egress_cidrs=dict(type='list', required=False),
        ephemeral_storage_policy=dict(type='str', required=False),
        haproxy_ca_chain=dict(type='str', required=False),
        haproxy_management_ip=dict(type='str', required=False),
        haproxy_management_port=dict(type='str', required=False, default='5556'),
        haproxy_password=dict(type='str', required=False),
        haproxy_ip_range_list=dict(type='list', required=False),
        haproxy_username=dict(type='str', required=False),
        image_storage_policy=dict(type='str', required=False),
        ingress_cidrs=dict(type='list', required=False),
        management_address_count=dict(type='int', required=False, default=5),
        management_dns_servers=dict(type='list', required=False),
        management_gateway=dict(type='str', required=False),
        management_netmask=dict(type='str', required=False),
        management_ntp_servers=dict(type='list', required=False),
        management_port_group=dict(type='str', required=False),
        management_starting_address=dict(type='str', required=False),
        master_storage_policy=dict(type='str', required=False),
        network_provider=dict(type='str', required=True, choices=['VSPHERE_NETWORK', 'NSXT_CONTAINER_PLUGIN']),
        nsx_edge_cluster=dict(type='str', required=False),
        pod_cidrs=dict(type='list', required=False),
        workload_dns_servers=dict(type='list', required=False),
        workload_gateway=dict(type='str', required=False),
        workload_netmask=dict(type='str', required=False),
        workload_ntp_servers=dict(type='list', required=False),
        workload_portgroup=dict(type='str', required=False),
        workload_ip_range_list=dict(type='list', required=False),
        services_cidr=dict(type='str', required=False),
        supervisor_size=dict(type='str', choices=['TINY', 'SMALL', 'MEDIUM', 'LARGE'], required=False), 
        state=dict(type='str', choices=['present', 'absent'], default='present', required=False),
        # storage_policy_name=dict(type='str', required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[
                                ('state', 'present', [
                                    'ephemeral_storage_policy', 'image_storage_policy', 'management_dns_servers', 
                                    'management_gateway', 'management_netmask', 'management_ntp_servers',
                                    'management_port_group', 'management_starting_address', 'master_storage_policy',
                                    'network_provider', 'services_cidr', 'supervisor_size', 'workload_dns_servers',
                                    'workload_ntp_servers'
                                    
                                ]),
                                ('network_provider', 'VSPHERE_NETWORK', [
                                    'haproxy_ca_chain', 'haproxy_management_ip', 'haproxy_password', 
                                    'haproxy_ip_range_list', 'haproxy_username', 'workload_dns_servers',
                                    'workload_gateway', 'workload_portgroup', 'workload_ip_range_list',
                                    'workload_netmask',
                                ]),
                                ('network_provider', 'NSXT_CONTAINER_PLUGIN', [
                                    'cluster_distributed_switch', 'egress_cidrs', 'ingress_cidrs', 
                                    'nsx_edge_cluster', 'pod_cidrs'
                                ]),
                            ]
    )

    vmware_namespace_cluster_manage = VmwareNamespaceClusterVdsManage(module)
    vmware_namespace_cluster_manage.process_state()


if __name__ == '__main__':
    main()
