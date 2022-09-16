#!/usr/bin/env python3

"""
This script generates a series of shell scripts which, when run:
- Allocate IP addresses to a virtual machine (mimicking a DHCP server);
- Configure those IP addresses statically into the virtual machine;
- Configure static routes into the virtual machine using systemd unit files;
- Restart services on the virtual machine as required.
It also generates a shell script to be run locally, which copies each of the
virtual machine scripts to that VM using scp and runs it using ssh.
"""

import sys
import re
from ipaddress import IPv4Network
from os.path import basename
from os import chmod
from stat import S_IRUSR, S_IXUSR, S_IRGRP, S_IXGRP, S_IROTH, S_IXOTH
from vsphere import VSphereVMList
from netconfig import NetworkConfigList


"""
The name of the shell script to be run locally, which configures all VMs.
"""
LOCAL_SCRIPT_FILENAME = 'scripts/netconfig.sh'
"""
The directory where systemd-networkd keeps its *.network files.
"""
SYSTEMD_NETWORK_FILE_DIR = '/etc/systemd/network'
"""
The file from which to read configuration for this script.
"""
SUBNET_CONFIG_FILE = 'networks.yaml'
"""
The name of the TKG management interface.
"""
MANAGEMENT_INTERFACE_NAME = 'eth0'
"""
Whether to configure virtual machines' network interfaces.
"""
CONFIGURE_INTERFACES = True
"""
Whether to configure virtual machines' IP routes.
"""
CONFIGURE_ROUTES = True


def get_ip_for_host(network_config, all_vms, my_hostname):
    """
    If the given virtual machine already has an interface on the given
    network, and that interface already has an IP address, then return that
    IP address.
    Otherwise, return an IP address on that network that is not currently
    used.
    """
    subnet_ip_generator = network_config.ip_generator()
    for ip in subnet_ip_generator:
        try:
            other_hostname = all_vms.ip_to_hostname(str(ip))
        except KeyError:
            # print("Unused IP: " + str(ip))
            return ip
        if other_hostname == my_hostname:
            # print("IP " + str(ip) + " being re-used by " + my_hostname)
            return ip
        # print("IP " + str(ip) + " already in use by " + other_hostname)
    raise("Exhausted IP addresses in subnet '" + network_config.name() + "'")


def create_systemd_network_definition_trunk(mac):
    """
    Create a systemd-networkd definition file, suitable for installation
    into /etc/systemd/network, for the trunk interface.
    """
    file_data = """
[Match]
MACAddress={mac}

[Network]
DHCP=no
""".format(
        mac=mac
    )
    return file_data


def create_systemd_network_definition_management(network_config):
    """
    Create a systemd-networkd definition file, suitable for installation
    into /etc/systemd/network, for the management interface.
    """
    file_data = """
[Match]
Name={interface_name}

[Link]
MTUBytes={mtu}

[Network]
DHCP=yes
IPv6AcceptRA=no
""".format(
        interface_name=MANAGEMENT_INTERFACE_NAME,
        mtu=str(network_config.mtu())
    )
    return file_data


def create_systemd_network_definition(
    mac,
    mtu,
    description,
    ipv4_cidr,
    dns_servers=[],
    dns_domains=[],
    routes=[]
):
    """
    Create a systemd-networkd definition file, suitable for installation
    into /etc/systemd/network, with the given settings.
    """
    file_data = """
[Match]
MACAddress={mac}

[Address]
Address={ipv4_cidr}

[Link]
MTUBytes={mtu}

[Network]
Description={description}
DHCP=no
""".format(
        mac=mac, ipv4_cidr=ipv4_cidr, mtu=str(mtu), description=description
    )
    if dns_domains:
        file_data = file_data + "Domains={dns_domains}\n".format(
            dns_domains=' '.join(dns_domains)
        )
    for dns_server in dns_servers:
        file_data = file_data + "DNS={dns_server}\n".format(
            dns_server=dns_server
        )
    for route in routes:
        file_data = file_data + """
[Route]
Destination={destination}
Gateway={gateway}
""".format(destination=route[0], gateway=route[1])
    return file_data


def generate_script_for_trunk(remote_script_fh, mac):
    file_data = create_systemd_network_definition_trunk(
        mac=mac
    )
    file_name = 'trunk.network'
    installed_file_path = SYSTEMD_NETWORK_FILE_DIR + '/' + file_name
    remote_script_fh.writelines("""
cat <<\"EOF\" > '{file_name}'
{file_data}
EOF
# Photon OS doesn't have a 'cmp' utility by default
mycmp() {{
    if [ $(md5sum \"$1\" \"$2\"|cut -f1 '-d '|sort -u|wc -l) -eq '2' ] ; then
        return 1
    else
        return 0
    fi
}}
if test -e '{installed_file_path}' && \\
mycmp '{file_name}' '{installed_file_path}' ; then
    true # Skip unchanged file
else
    # Install nonexistent/changed file
    chmod ugo+r '{file_name}'
    cp '{file_name}' '{installed_file_path}'
    chmod ugo+r \"{systemd_network_file_dir}\"/*
    must_restart_services=true
fi
    """.format(
            file_name=file_name,
            installed_file_path=installed_file_path,
            file_data=file_data,
            systemd_network_file_dir=SYSTEMD_NETWORK_FILE_DIR
        )
    )


def generate_script_for_interface(
    all_vms,
    network_config,
    remote_script_fh,
    mac,
    hostname,
    dns_servers,
    dns_domains
):
    """
    Generate a shell script which configures the network interface with the
    given MAC address on the VM with the given hostname.
    """
    routes = []
    ip_address = all_vms.get_existing_ip(hostname, network_config.name())
    if ip_address is None:
        ip_address = get_ip_for_host(
            network_config,
            all_vms,
            hostname
        )
    netmask = IPv4Network('0.0.0.0/' + network_config.netmask())
    file_data = create_systemd_network_definition(
        mac=mac,
        mtu=network_config.mtu(),
        description=network_config.name(),
        ipv4_cidr=str(ip_address) + '/' + str(netmask.prefixlen),
        dns_servers=dns_servers,
        dns_domains=dns_domains,
        routes=network_config.static_routes()
    )
    file_name = network_config.sanitised_name() + '.network'
    installed_file_path = SYSTEMD_NETWORK_FILE_DIR + '/' + file_name
    remote_script_fh.writelines("""
cat <<\"EOF\" > '{file_name}'
{file_data}
EOF
# Photon OS doesn't have a 'cmp' utility by default
mycmp() {{
    if [ $(md5sum \"$1\" \"$2\"|cut -f1 '-d '|sort -u|wc -l) -eq '2' ] ; then
        return 1
    else
        return 0
    fi
}}
if test -e '{installed_file_path}' && \\
mycmp '{file_name}' '{installed_file_path}' ; then
    true # Skip unchanged file
else
    # Install nonexistent/changed file
    chmod ugo+r '{file_name}'
    cp '{file_name}' '{installed_file_path}'
    chmod ugo+r \"{systemd_network_file_dir}\"/*
    must_restart_services=true
fi

    """.format(
            file_name=file_name,
            installed_file_path=installed_file_path,
            file_data=file_data,
            systemd_network_file_dir=SYSTEMD_NETWORK_FILE_DIR
        )
    )


def one_management_route_command(management_route):
    """
    Generate a shell script which adds the given route if no route to the
    given destination already exists, or successfully does nothing if a route
    to the given destination already exists.
    """
    destination = str(management_route[0])
    if destination.endswith('/32'):
        destination = destination[:-3]
    return (
        "("
        "/usr/sbin/ip route | fgrep {destination} >/dev/null 2>&1 "
        "|| /usr/sbin/ip route add {destination} via {gateway} "
        ")"
    ).format(
        destination=destination,
        gateway=management_route[1]
    )


def all_management_route_commands(management_routes):
    """
    Generate a a series of shell commands which each add one of the given
    routes.
    """
    for management_route in management_routes:
        yield one_management_route_command(management_route)


def management_route_script(management_routes):
    """
    Generate a complete shell script which adds all of the given routes.
    """
    return " && ".join(all_management_route_commands(management_routes))


def generate_script_for_vm(
    local_script_fh,
    all_vms,
    vminfo,
    all_network_configs
):
    """
    Generate a shell script which configures the given virtual machine.
    """
    hostname = vminfo.name()
    management_ip = vminfo.get_management_ip()
    print("Generating script for " + hostname)
    management_network_config = all_network_configs.management_network_config()
    if CONFIGURE_ROUTES:
        if vminfo.is_control_plane():
            if vminfo.is_management_cluster():
                management_routes = (
                    all_network_configs.management_routes_management_control_plane()
                )
            else:
                management_routes = (
                    all_network_configs.management_routes_workload_control_plane()
                )
        elif vminfo.is_load_balancer():
            if vminfo.is_management_cluster():
                management_routes = (
                    all_network_configs.management_routes_management_load_balancer()
                )
            else:
                management_routes = (
                    all_network_configs.management_routes_workload_load_balancer()
                )
        else:
            if vminfo.is_management_cluster():
                management_routes = (
                    all_network_configs.management_routes_management_worker()
                )
            else:
                management_routes = (
                    all_network_configs.management_routes_workload_worker()
                )
    remote_script_filename = 'scripts/' + hostname + ".sh"
    with open(remote_script_filename, 'w') as remote_script_fh:
        remote_script_fh.writelines("""
cd $(mktemp --directory)
must_restart_services=false
""")
        if CONFIGURE_ROUTES:
            remote_script_fh.writelines("""
cat <<\"EOF\" > /etc/systemd/system/custom-routes.service
[Unit]
Description=Apply custom routes
After=network-online.target
Requires=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/sh -c 'while true ; do """)
            remote_script_fh.writelines(
                management_route_script(management_routes)
            )
            remote_script_fh.writelines(""" && break ; sleep 5 ; done'

[Install]
RequiredBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/custom-routes.service
systemctl daemon-reload
systemctl enable custom-routes
""")
        if CONFIGURE_INTERFACES:
            file_name = MANAGEMENT_INTERFACE_NAME + '.network'
            file_data = create_systemd_network_definition_management(
                management_network_config
            )
            installed_file_path = SYSTEMD_NETWORK_FILE_DIR + '/' + file_name
            remote_script_fh.writelines("""
cat <<\"EOF\" > '{file_name}'
{file_data}
EOF
# Photon OS doesn't have a 'cmp' utility by default
mycmp() {{
    if [ $(md5sum \"$1\" \"$2\"|cut -f1 '-d '|sort -u|wc -l) -eq '2' ] ; then
        return 1
    else
        return 0
    fi
}}
if test -e '{installed_file_path}' && \\
mycmp '{file_name}' '{installed_file_path}' ; then
    true # Skip unchanged file
else
    # Install nonexistent/changed file
    chmod ugo+r '{file_name}'
    cp '{file_name}' '{installed_file_path}'
    chmod ugo+r \"{systemd_network_file_dir}\"/*
    must_restart_services=true
fi

""".format(
                file_name=file_name,
                installed_file_path=installed_file_path,
                file_data=file_data,
                systemd_network_file_dir=SYSTEMD_NETWORK_FILE_DIR)
            )
            mac_to_net = all_vms.build_mac_to_net_mapping(vminfo)
            interface_filenames = []
            for vm_network_interface in vminfo.interfaces():
                mac = vm_network_interface.mac_address()
                network_name = mac_to_net[mac]
                if vm_network_interface.is_management():
                    continue  # Special case handled above
                elif vm_network_interface.is_trunk():
                    interface_filename = generate_script_for_trunk(
                        remote_script_fh,
                        mac
                    )
                elif not vm_network_interface.connected():
                    """
                    This is not an error condition, because this could be a
                    Calico interface
                    """
                    """
                    raise ValueError(
                        "VM '" + hostname
                        + "' has non-trunk, non-connected interface with MAC '"
                        + vm_network_interface.mac_address()
                        + "' connected to network '"
                        + vm_network_interface.network_name() + "'"
                    )
                    """
                    continue  # Interface not connected to a network
                else:
                    network_config = all_network_configs.get_network_config(
                        network_name
                    )
                    interface_filename = generate_script_for_interface(
                        all_vms,
                        network_config,
                        remote_script_fh,
                        mac,
                        hostname,
                        dns_servers=all_network_configs.dns_servers(),
                        dns_domains=all_network_configs.dns_domains(),
                    )
                interface_filenames.append(interface_filename)
            remote_script_fh.writelines("""
for network_file in '{SYSTEMD_NETWORK_FILE_DIR}/'* ; do
    b=$(basename \"$network_file\")
    if test -e \"$b\" ; then
        true # We generated this file
    else
        rm -f \"$network_file\" # Remove file we didn't generate
        must_restart_services=true
    fi
done

if $must_restart_services ; then
    systemctl restart systemd-networkd && \\
    systemctl restart custom-routes && \\
    sleep 5 && \\
    sudo systemctl restart kubelet
fi
""".format(SYSTEMD_NETWORK_FILE_DIR=SYSTEMD_NETWORK_FILE_DIR))
    local_script_fh.writelines("""
scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=No \\
'{remote_script_filename}' 'capv@{management_ip}:/tmp/{basename}' && \\
ssh -n -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=No \\
'capv@{management_ip}' 'sudo sh \"/tmp/{basename}\"'
""".format(
        remote_script_filename=remote_script_filename,
        management_ip=management_ip,
        basename=basename(remote_script_filename)
    ))


if __name__ == "__main__":
    """
    Generate a series of shell scripts which configure each of the virtual
    machines in the given cluster.
    """
    environment = sys.argv[1]
    cluster_name = sys.argv[2]
    subnet_configs = NetworkConfigList(SUBNET_CONFIG_FILE)
    all_vms = VSphereVMList("vminfo.json")
    with open(LOCAL_SCRIPT_FILENAME, 'w') as local_script_fh:
        for vminfo in all_vms.vms_in_cluster(environment, cluster_name):
            generate_script_for_vm(
                local_script_fh, all_vms, vminfo, subnet_configs
            )
    chmod(
        LOCAL_SCRIPT_FILENAME,
        S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH
    )
    sys.exit(0)
