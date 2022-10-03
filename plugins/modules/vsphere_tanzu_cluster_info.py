#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type


DOCUMENTATION = r'''
---
module: vsphere_tanzu_cluster_info
short_description: Gather information about Tanzu configuration of a vSphere Cluster
description:
- Return all Tanzu related configuration from a vSphere cluster
author:
- Matt Proud (@laidbackware)
notes:
- Tested on vSphere 7.0u1
requirements:
- python >= 3.5
- vSphere Automation SDK 7.0u2 or higher
- community.vmware modules either from Ansible Galaxy or as part of the community collections package
options:
    cluster_name: 
      description:
      - The name of the name of the vsphere cluster to configure
      type: str
      required: True
extends_documentation_fragment:
- community.vmware.vmware_rest_client.documentation

'''
EXAMPLES = r'''
- name: Enable Namespaces on Cluster
  vsphere_tanzu_cluster_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
    cluster_name: tkgs-cluster
  delegate_to: localhost
'''

RETURN = r'''
cluster_info:

'''

import uuid
from time import sleep
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.vmware.plugins.module_utils.vmware_rest_client import VmwareRestClient
from com.vmware.vapi.std.errors_client import Unsupported
import urllib3
urllib3.disable_warnings()

HAS_VAUTOMATION_PYTHON_SDK = False
try:
    from com.vmware.vcenter.namespace_management_client import Clusters
    HAS_VAUTOMATION_PYTHON_SDK = True
except ImportError:
    pass


class VmwareNamespaceClusterVdsManage(VmwareRestClient):
    def __init__(self, module):
        """Constructor."""
        super(VmwareNamespaceClusterVdsManage, self).__init__(module)

        self.cluster_object = Clusters(self.api_client._stub_config)
        self.cluster_name = self.params.get('cluster_name')
        self.cluster_id = self.get_object_by_name(self.cluster_name, 'cluster')
       
    def get_cluster_info(self):
        try:
            cluster_info = self.cluster_object.get(self.cluster_id)
        except Unsupported:
            self.module.fail_json(msg="Cluster named '%s' does not have workload management enabled" % self.cluster_name)

        self.module.exit_json(exists=False, changed=False, cluster_info=cluster_info.to_dict())

    # return the internal identifier of an object
    def get_object_by_name(self, object_name, object_type):
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
    vmware_namespace_cluster_manage.get_cluster_info()


if __name__ == '__main__':
    main()
