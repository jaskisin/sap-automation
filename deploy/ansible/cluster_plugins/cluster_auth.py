#!/usr/bin/python

# Copyright: (c) 2022, William Sheehan <willksheehan@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cluster_auth

short_description: authenticates nodes that will constitute a cluster

version_added: "1.0"

description: authenticates the user on one or more nodes to be used in a cluster on RHEL operating system

options:
    state:
        description:
            - "present" ensures the nodes are authenticated
            - "absent" ensures the nodes are deauthenticated
        required: false
        choices: ["present", "absent"]
        default: "present"
        type: str
    nodes:
        description:
            - the nodes to authenticate or deauthenticate
            - a string of one or more nodes separated by spaces
        required: true
        type: str
    username:
        description:
            - the username of the cluster administrator
        required: false
        default: "hacluster"
        type: str
    password:
        description:
            - the password of the cluster administrator
            - required when state is present
        required: false
        type: str

author:
    - William Sheehan (@wksheehan)
'''

EXAMPLES = r'''
- name: Authenticate user hacluster on node1 for both the nodes in a two-node cluster (node1 and node2)
  cluster_auth:
    nodes: node1 node2
    username: hacluster
    password: testpass
'''

import json
import os.path
from ansible.module_utils.basic import AnsibleModule
from helper_functions import get_os_name_and_version, execute_command, get_pcs_version, get_command_dictionary, replace_placeholders
from distutils.spawn import find_executable

def run_module():

    # ==== SETUP ====

    module_args = dict(
        state=dict(required=False, default="present", choices=["present", "absent"]),
        nodes=dict(required=True),
        username=dict(required=False, default="hacluster"),
        password=dict(required=False, no_log=True)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False,
        message=""
    )

    os_name, os_version = get_os_name_and_version(module, result)
    state       = module.params["state"]
    nodes       = module.params["nodes"]
    username    = module.params["username"]
    password    = module.params["password"]


    # ==== INITIAL CHECKS ====

    if find_executable("pcs") is None:
        module.fail_json(msg="'pcs' executable not found. Install 'pcs'.")
    if state == "present" and password is None:
        module.fail_json(msg="Must specify password when state is present", **result)

    pcs_version = get_pcs_version(module, result)

    commands = get_command_dictionary(module, "auth", result)

    values = {}
    values["nodes"] = nodes
    values["username"] = username
    values["password"] = password

    replace_placeholders(commands, values)

    # ==== MAIN CODE ====

    if os.path.isfile('/var/lib/pcsd/tokens') and pcs_version == '0.9':
        tokens_file = open('/var/lib/pcsd/tokens', 'r+')
        # load JSON tokens
        tokens_data = json.load(tokens_file)
        result['tokens_data'] = tokens_data['tokens']
    if os.path.isfile('/var/lib/pcsd/known-hosts') and pcs_version in ['0.10', '.0.11', '0.12']:
        tokens_file = open('/var/lib/pcsd/known-hosts', 'r+')
        # load JSON tokens
        tokens_data = json.load(tokens_file)
        result['tokens_data'] = tokens_data['known_hosts']

    pcs_version_rc, pcs_version_out, pcs_version_err = module.run_command(commands[pcs_version]["status"])

    if state == "present" and pcs_version_rc != 0:
        result["changed"] = True
        cmd = commands[pcs_version]["authenticate"]
        execute_command(module, result, cmd,
                    "Nodes were successfully authenticated",
                    "Failed to authenticate one or more nodes")
    elif (state == 'absent' and tokens_data and (
            (pcs_version == '0.9' and nodes in tokens_data['tokens']) or
            (pcs_version in ['0.10', '0.11', '0.12'] and nodes in tokens_data['known_hosts']))):
        result["changed"] = True
        if pcs_version == '0.9':
            del tokens_data['tokens'][nodes]
            del tokens_data['ports'][nodes]
            tokens_data['data_version'] += 1
            tokens_file.seek(0)
            json.dump(tokens_data, tokens_file, indent=4)
            tokens_file.truncate()
        else:
            cmd = commands[pcs_version]["deauthenticate"]
            execute_command(module, result, cmd,
                        "Nodes were successfully deauthenticated",
                        "Failed to deauthenticate one or more nodes")
    else:
        result['changed'] = False
        module.exit_json(**result)

    # Success
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
