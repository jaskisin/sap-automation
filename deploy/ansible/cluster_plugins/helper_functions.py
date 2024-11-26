# ==== Helper functions to be used across the cluster modules ====

# Returns the operating system name (e.g. Suse, RedHat) and major version (e.g. 8)
def get_os_name_and_version(module, result):
    cmd = "egrep '^NAME=' /etc/os-release | awk -F'[=]' '{print $2}' | tr -d '\"[:space:]'"
    rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
    if rc != 0:
        module.fail_json("Could not identify an OS distribution", **result)
    else:
        if "SLES" in out:
            os_name = "Suse"
        elif "RedHat" in out:
            os_name = "RedHat"
        else:
            module.fail_json("Unrecognized linux distribution", **result)
    if os_name == "Suse":
        os_version = "all"
    else:
        cmd = "egrep '^VERSION_ID=' /etc/os-release | awk -F'[=]' '{print $2}' | tr -d '\"[:space:]'"
        rc, out, err = module.run_command(cmd, use_unsafe_shell=True)
        if rc != 0:
            module.fail_json("Could not identify OS version", **result)
        else:
            os_version = out.split('.')[0]
    return os_name, os_version

def get_pcs_version(module, result):
    supported_versions = ['0.9', '0.10', '0.11', '0.12']
    os, version = get_os_name_and_version(module, result)
    if os != "RedHat":
        module.fail_json("This module only supports RedHat", **result)
    else:
        cmd = "pcs --version"
        rc, out, err = module.run_command(cmd)
        if rc == 0:
            pcs_version = out.split('.')[0] + '.' + out.split('.')[1]
            if pcs_version not in supported_versions:
                module.fail_json("Unsupported pcs version: " + pcs_version, **result)
        else:
            module.fail_json(msg="pcs --version exited with errors (" + rc + "): " + out + err)
    return pcs_version

# Executes a command and handles the success or failure
def execute_command(module, result, cmd, success, failure, unsafe=False):
    rc, out, err = module.run_command(cmd, use_unsafe_shell=unsafe)
    if rc == 0:
        result["message"] += success
        return out
    else:
        result["changed"] = False
        result["stdout"] = out
        result["error_message"] = err
        result["command_used"] = cmd
        module.fail_json(msg=failure, **result)

def get_command_dictionary(module, cluster_ops, result):
    os_name, os_version = get_os_name_and_version(module, result)

    commands                                             = {}
    commands["auth"]                                     = {}
    commands["auth"]["RedHat"]                           = {}
    commands["auth"]["Suse"  ]                           = {}
    commands["auth"]["Suse"  ]["all"]                    = {}
    commands["auth"]["RedHat"]["0.9"]                    = {}
    commands["auth"]["RedHat"]["0.10"]                   = {}
    commands["auth"]["RedHat"]["0.11"]                   = {}
    commands["auth"]["RedHat"]["0.12"]                   = {}
    commands["auth"]["RedHat"]["0.9" ]["status"]         = "pcs cluster pcsd-status {nodes}"
    commands["auth"]["RedHat"]["0.10"]["status"]         = "pcs cluster pcsd-status {nodes}"
    commands["auth"]["RedHat"]["0.11"]["status"]         = "pcs cluster pcsd-status {nodes}"
    commands["auth"]["RedHat"]["0.12"]["status"]         = "pcs pcsd status {nodes}"
    commands["auth"]["RedHat"]["0.9" ]["authenticate"]   = "pcs cluster auth {nodes} -u {username} -p {password} --local"
    commands["auth"]["RedHat"]["0.10"]["authenticate"]   = "pcs cluster auth {nodes} -u {username} -p {password}"
    commands["auth"]["RedHat"]["0.11"]["authenticate"]   = "pcs cluster auth {nodes} -u {username} -p {password}"
    commands["auth"]["RedHat"]["0.12"]["authenticate"]   = "pcs cluster auth {nodes} -u {username} -p {password}"
    commands["auth"]["RedHat"]["0.10"]["deauthenticate"] = "pcs host deauth {nodes}"
    commands["auth"]["RedHat"]["0.11"]["deauthenticate"] = "pcs host deauth {nodes}"
    commands["auth"]["RedHat"]["0.12"]["deauthenticate"] = "pcs host deauth {nodes}"

    commands["init"]["RedHat"]["0.9" ]["setup"]          = "pcs cluster setup --name {desired_cluster_name} {nodes} --token {token}"
    commands["init"]["RedHat"]["0.10"]["setup"]          = "pcs cluster setup {desired_cluster_name} {nodes} totem token={token}"
    commands["init"]["RedHat"]["0.11"]["setup"]          = "pcs cluster setup {desired_cluster_name} {nodes} totem token={token}"
    commands["init"]["RedHat"]["0.12"]["setup"]          = "pcs cluster setup {desired_cluster_name} {nodes} totem token={token}"
    commands["init"]["Suse"  ]["all" ]["setup"]          = "ha-cluster-init -y --name '{desired_cluster_name}' --interface eth0 --no-overwrite-sshkey --nodes '{nodes}'"
    commands["init"]["RedHat"]["0.9" ]["destroy"]        = "pcs cluster destroy --all"
    commands["init"]["RedHat"]["0.10"]["destroy"]        = "pcs cluster destroy --all"
    commands["init"]["RedHat"]["0.11"]["destroy"]        = "pcs cluster destroy --all"
    commands["init"]["RedHat"]["0.12"]["destroy"]        = "pcs cluster destroy --all"
    commands["init"]["Suse"  ]["all" ]["destroy"]        = "crm cluster remove -y -c %s %s --force" # % (curr_node, " ".join(nodes_set))
    commands["init"]["RedHat"]["0.9" ]["add"]            = "pcs cluster node add "
    commands["init"]["RedHat"]["0.10"]["add"]            = "pcs cluster node add "
    commands["init"]["RedHat"]["0.11"]["add"]            = "pcs cluster node add "
    commands["init"]["RedHat"]["0.12"]["add"]            = "pcs cluster node add "
    commands["init"]["Suse"  ]["all" ]["add"]            = "crm cluster add -y "
    commands["init"]["RedHat"]["7"  ]["remove"]         = "pcs cluster node remove %s --force"
    commands["init"]["RedHat"]["8"  ]["remove"]         = "pcs cluster node remove %s --force"
    commands["init"]["Suse"  ]["all"]["remove"]         = "crm cluster remove -y %s --force"
    commands["init"]["RedHat"]["7"  ]["start"]          = "pcs cluster start"
    commands["init"]["RedHat"]["8"  ]["start"]          = "pcs cluster start"
    commands["init"]["Suse"  ]["all"]["start"]          = "crm cluster start"
    commands["init"]["RedHat"]["7"  ]["stop"]           = "pcs cluster stop"
    commands["init"]["RedHat"]["8"  ]["stop"]           = "pcs cluster stop"
    commands["init"]["Suse"  ]["all"]["stop"]           = "crm cluster stop"
    commands["init"]["RedHat"]["7"  ]["status"]         = "pcs status"
    commands["init"]["RedHat"]["8"  ]["status"]         = "pcs status"
    commands["init"]["Suse"  ]["all"]["status"]         = "crm status"
    commands["init"]["RedHat"]["7"  ]["online"]         = "pcs status | grep '^Online:'"
    commands["init"]["RedHat"]["8"  ]["online"]         = "pcs status | grep '^  \* Online:'"
    commands["init"]["Suse"  ]["all"]["online"]         = "crm status | grep 'Online:'"
    commands["init"]["Suse"  ]["all"]["join"]           = "ha-cluster-join -y -c %s --interface eth0" % existing_node
    commands["init"]["RedHat"]["regex"]                 = r"ring0_addr\s*:\s*([\w.-]+)\s*"
    commands["init"]["Suse"  ]["regex"]                 = r"host\s*([\w.-]+);"
    commands["init"]["RedHat"]["file"]                  = "/etc/corosync/corosync.conf"
    commands["init"]["Suse"  ]["file"]                  = "/etc/csync2/csync2.cfg"

    matching_commands = commands.get(cluster_ops, {}).get(os_name, {})

    return matching_commands

def replace_placeholders(module, dictionary, values, result):
    for key, value in dictionary.items():
        if isinstance(value, dict):  # If the value is a nested dictionary, recurse
            replace_placeholders(value, values)
        elif isinstance(value, str):  # If the value is a string, replace placeholders
            dictionary[key] = value.format(**values)


## code to check the status of cluster packages and daemons
