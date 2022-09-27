# ansible-for-vsphere-tanzu

This repo contains proof of concept module for deploying vSphere with Tanzu Kubernetes.

## Dependencies
```
pip install ansible
pip install --upgrade pip setuptools
pip install --upgrade git+https://github.com/vmware/vsphere-automation-sdk-python.git
```

## Instructions
Example Ansible task usage can be found in the [module](https://github.com/laidbackware/ansible-for-vsphere-tanzu/blob/ba544ea1c430e0374776e35c9163c6f13724cf67/library/vsphere_tanzu_cluster_manage.py#L299)
