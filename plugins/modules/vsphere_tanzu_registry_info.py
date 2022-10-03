#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vsphere_tanzu_registry_info
short_description: Gather information about configuration state of Kubernetes on a vSphere Cluster
description:
- TODO
author:
- Matt Proud (@laidbackware)
notes:
- Tested on vSphere 7.0u1
requirements:
- python >= 3.5
# - PyVmomi
- vSphere Automation SDK 7.0u1 or higher
- community.vmware modules either from Ansible Galaxy or as part of the community collections package
options:
    
extends_documentation_fragment:
- community.vmware.vmware_rest_client.documentation

'''
EXAMPLES = r'''
- name: Enable Namespaces on Cluster
  vsphere_tanzu_registry_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    cluster_name: tkgs-cluster
  delegate_to: localhost
'''

RETURN = r'''
namespace_cluster_vds_info:

'''

import uuid
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.vmware.plugins.module_utils.vmware_rest_client import VmwareRestClient
from com.vmware.vapi.std.errors_client import Unsupported
import urllib3
urllib3.disable_warnings()

from com.vmware.vcenter.content.registries_client import Harbor


class VmwareNamespaceClusterVdsManage(VmwareRestClient):
    def __init__(self, module):
        """Constructor."""
        super(VmwareNamespaceClusterVdsManage, self).__init__(module)

        self.registry_object = Harbor(self.api_client._stub_config)
        self.cluster_name = self.params.get('cluster_name')
        self.cluster_id = self.get_cluster_by_name(self.cluster_name, 'cluster')
       
    def get_registry_info(self):
        try:
            registry_info = self.registry_object.get(self.cluster_id)
        except Unsupported:
            self.module.fail_json(msg="Cluster named '%s' does not have workload management enabled" % self.cluster_name)

        self.module.exit_json(exists=False, changed=False, content_lib_details=registry_info.to_dict())

    # return the internal identifier of an object
    def get_cluster_by_name(self, object_name, object_type):
        object_list = self.api_client.vcenter.Cluster.list()
        for item in object_list:
            if item.name == object_name:
                object_id = eval("item.%s" % object_type)
                return object_id
        self.module.fail_json(msg="%s named %s was not found" % (object_type, object_name))


def main():
    argument_spec = VmwareRestClient.vmware_client_argument_spec()
    argument_spec.update(
        cluster_name=dict(type='str', required=True),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False,
                          )

    vmware_namespace_cluster_manage = VmwareNamespaceClusterVdsManage(module)
    vmware_namespace_cluster_manage.get_registry_info()


if __name__ == '__main__':
    main()
