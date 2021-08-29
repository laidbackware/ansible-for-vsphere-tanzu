#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vmware_namespace_cluster_vds_manager
short_description: Enable, disable and update namespaces on a vSphere cluster
description:
- TODO
author:
- Matt Proud (@laidbackware)
notes:
- Tested on vSphere 7.0u1
requirements:
- python >= 3.5
- PyVmomi
- vSphere Automation SDK
options:
hostname: '{{ vcenter_hostname }}'
    content_library_name: 
      description:
      - The name of the content library hosting VM images
      - This is required only if I(state) is set to C(present).
      type: str
      required: True
    cluster_name: 
      description:
      - The name of the name of the vsphere cluster to configure
      type: str
      required: True
    dns_search_domains: 
      description:
      - The dns search domain to assign to the management cluster
      type: str
    # dns_servers: 
    #   description:
    #   - The name of the name of the vsphere cluster to configure
    #   type: str
    #   required: True
    haproxy_ca_chain: |
    haproxy_management_ip: "192.168.0.173"
    haproxy_management_port: "5556"
    haproxy_password: haproxy
    haproxy_username: password_here
    haproxy_ip_range_list: ["172.31.0.128/26"]
    management_address_count: 5
    management_dns_servers:
      description:
      - List of strings containing DNS server IPs for the management network
      - This is required only if I(state) is set to C(present).
      type: list
      required: True
    management_gateway: "192.168.0.1"
    management_netmask: "255.255.252.0"
    management_port_group: routed-pg
    management_starting_address: "192.168.0.174"
    ntp_servers: ["192.168.0.1"]
    workload_dns_servers:
      description:
      - List of strings containing DNS server IPs for the workload network
      - This is required only if I(state) is set to C(present).
      type: list
      required: True
    workload_gateway: "172.31.0.1"
    workload_netmask: "255.255.255.0"
    workload_portgroup: private-pg
    # workload_range_starting_ip: "172.31.0.3"
    # workload_range_count: 40
    workload_ip_range_list: ["172.31.0.32/27"]
    services_cidr: "10.255.255.0"
    supervisor_size: TINY
    storage_policy_name: "tkgs-storage-policy"
    
extends_documentation_fragment:
- community.vmware.vmware_rest_client.documentation

'''
EXAMPLES = r'''
- name: Enable Namespaces on Cluster
  community.vmware.vmware_namespace_cluster_vds_manager:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    content_library_name: "tkgs-library"
    cluster_name: tkgs-cluster
    dns_search_domains: ["home.local"]
    dns_servers: ["192.168.0.110"]
    haproxy_ca_chain: |
        -----BEGIN CERTIFICATE-----
        MIIDoTCCAomgAwIBAgIJAME387BtGGikMA0GCSqGSIb3DQEBBQUAMG4xCzAJBgNV
        BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlQYWxvIEFsdG8x
        DzANBgNVBAoMBlZNd2FyZTENMAsGA1UECwwEQ0FQVjEWMBQGA1UEAwwNMTkyLjE2
        OC4wLjE3MzAeFw0yMDEyMTgxMzI0NDhaFw0zMDEyMTYxMzI0NDhaMG4xCzAJBgNV
        BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlQYWxvIEFsdG8x
        DzANBgNVBAoMBlZNd2FyZTENMAsGA1UECwwEQ0FQVjEWMBQGA1UEAwwNMTkyLjE2
        OC4wLjE3MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpaFdTntwKj
        7iEThLB7+GA4SIxJLHXmnh05Y2L0lZ0TMz2h2tsnI+Hv2x9QlVQtIiSpTxb89xl8
        3qE/IBvaNc/8vRY8h4gaFbkh0GS+9JoQzPFYnZrI9fzNwh2cyKqigzzJEe61JX0p
        XhN42lzdziUu2qYgAvwLPne3UCKI/CenU0WHOcq61cCEaE07nPKbjKgLD20SSiv/
        f+4JnvzeAU7d6De+78mQIxTCyBeQG9ZeE/y22fHoNbIu5rQKIfhYtyDuv8mpC3Z3
        HyRKL4z/DcO0aLanbYQsFB0IhI1ZZvkqcRIarI0atPJPjxcl7xHtcojTTfpy0QvH
        K77D81ZEQB8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
        AYYwHQYDVR0OBBYEFC+EVdoW1yy6sv1S58G6imTwXRGbMA0GCSqGSIb3DQEBBQUA
        A4IBAQBn9U5aJSOmLRzmHWxgxfnu+28ksOCsuVpBVHm6+q7mrA/ArbuMncUBbnO1
        lCxDTJq+LOjAtDJeMhIDEPnCRBeBcrsvvoRIV2YR1kvrhCaWZoNTT07Jm9K5wBYx
        BTbJdvnp7kI0e/sgpRlRGFO/31ey5ItknQXGCTJ4qzp3KbtQ5qz+dvGz0iFykj31
        DYTqg5Da9WYBTnCm2a641OuoVfkK9Toq5kISTNkoi8JLhlJwQUuRFRE6OJfiLCQs
        0pC0Q8G1u2ToTZE0jntjy4BzxGZq26A/SrpFP/d8dksjo1IpRNLvA26+BJ7Ir/qY
        r32oIPyK4InlL/FMoVrmefDRTAwy
        -----END CERTIFICATE-----
    haproxy_management_ip: "192.168.0.173"
    haproxy_management_port: "5556"
    haproxy_password: haproxy
    haproxy_username: password_here
    haproxy_ip_range_list: ["172.31.0.128/26"]
    management_address_count: 5
    management_gateway: "192.168.0.1"
    management_port_group: routed-pg
    management_netmask: "255.255.252.0"
    management_starting_address: "192.168.0.174"
    ntp_servers: ["192.168.0.1"]
    workload_gateway: "172.31.0.1"
    workload_netmask: "255.255.255.0"
    workload_portgroup: private-pg
    # workload_range_starting_ip: "172.31.0.3"
    # workload_range_count: 40
    workload_ip_range_list: ["172.31.0.32/27"]
    services_cidr: "10.255.255.0"
    supervisor_size: TINY
    storage_policy_name: "tkgs-storage-policy"
    state: present
  delegate_to: localhost
  async: 1800
  poll: 5

- name: Disable Namespaces on Cluster
  community.vmware.vmware_namespace_cluster_vds_manager:
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
import uuid, ipaddress
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.vmware.plugins.module_utils.vmware_rest_client import VmwareRestClient
import urllib3
urllib3.disable_warnings()
from com.vmware.vcenter.content.registries_client import Harbor


class VmwareNamespaceClusterVdsManage(VmwareRestClient):
    def __init__(self, module):
        """Constructor."""
        super(VmwareNamespaceClusterVdsManage, self).__init__(module)

        self.registry_object = Harbor(self.api_client._stub_config)
        self.vsphere_api_object_mapping = {
            'network': self.api_client.vcenter.Network,
            'cluster': self.api_client.vcenter.Cluster,
            'policy': self.api_client.vcenter.storage.Policies
        }
        self.cluster_name = self.params.get('cluster_name')
        self.cluster_id = self.get_object_by_name(self.cluster_name, 'cluster')
        self.registry_storage_policy = self.params.get('registry_storage_policy')
        

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
                'absent': self.state_enable_registry,
            }
        }
        namespace_cluster_states[self.desired_state][self.check_namespace_cluster_status(self.desired_state)]()

    def check_namespace_cluster_status(self, desired_state):
        """
        Check if Workload Management is enabled for a specific cluster
        Returns: 'present' if workload management is enabled or configured, else 'absent'
        """
        try:
            existing_cluster_status = self.registry_object.get(self.cluster_id).config_status
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

    # Gets the internal identifier of an object
    def get_object_by_name(self, object_name, object_type):
        object_list = self.vsphere_api_object_mapping[object_type].list()
        for item in object_list:
            if item.name == object_name:
                object_id = eval("item.%s" % object_type)
                return object_id
        self.module.fail_json(msg="%s named %s was not found" % (object_type, object_name))

    def enable_registry(self, registry_spec):
        self.registry_object.create(self.cluster_id, registry_spec)

        error_count = 0
        errors_to_tollerate = 48
        # Wait until workload management reports as configured
        while True:
            registry_object = self.registry_object.get(self.cluster_id)
            cluster_status = registry_object.config_status
            
            if cluster_status == 'RUNNING':
                break
            elif cluster_status == 'ERROR':
                # Tollerate errors as it seems to randomly enter error states and then recover
                error_count += 1
                if error_count > errors_to_tollerate:
                    cluster_messages = registry_object.messages
                    self.module.fail_json(
                        msg="Enabling workload management on [%s] failed, status [%s] with error %s" % 
                            (self.cluster_name, cluster_status, cluster_messages)
                    )
            sleep(5)

    def state_enable_registry(self):
        """
        Enable workload management on a cluster using vSphere networking.
        """

        registry_spec = self.registry_object.CreateSpec()
        
        if self.module.check_mode:
            action = "would have been enabled"
        else:
            self.enable_registry(registry_spec)
            action = 'enabled'
        
        self.module.exit_json(
            changed=True,
            namespace_cluster_results = dict(
                msg="Registry on cluster '%s' %s." % (self.cluster_name, action),
                cluster_name=self.cluster_name,
                cluster_id=self.cluster_id
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
        self.registry_object.delete(self.cluster_id)
        self.module.exit_json(
            changed=True,
            namespace_cluster_results=dict(
            msg="Registry on cluster '%s' has been deleted." % self.cluster_name,
                cluster_name=self.cluster_name,
                cluster_id=self.cluster_id,
            )
        )


def main():
    argument_spec = VmwareRestClient.vmware_client_argument_spec()
    argument_spec.update(
        cluster_name=dict(type='str', required=True),
        garbage_collection=dict(type='str', required=False),
        registry_storage_policy=dict(type='str', required=False),
        registry_storage_limit=dict(type='str', required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_if=[
                                ('state', 'present', ['registry_storage_policy']),
                            ]
    )

    vmware_namespace_cluster_manage = VmwareNamespaceClusterVdsManage(module)
    vmware_namespace_cluster_manage.process_state()


if __name__ == '__main__':
    main()
