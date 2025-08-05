#!/usr/bin/env -S python3 -x
#
# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v1.0 as shown at https://oss.oracle.com/licenses/upl.
#
# This module contains reusable Python functions that are shared across multiple scripts in the project.
# It serves as a centralized utility library to promote code reuse, reduce duplication, and maintain consistency.

# By isolating common logic here, we aim to improve maintainability and make the codebase easier to understand
# and extend—both for internal development and external contributors.
#
# Module written by Antoun Moubarak, Cloud Architecture Specialist

import oci
import sys
import logging
import time
import json
from oci.util import to_dict
import os

def prepare_regions_file(source_region,destination_region,current_directory,base_config_file_name,script_name):
    regions_file = current_directory + "/" + base_config_file_name + "_" + script_name + "." + time.strftime("%Y%m%d%H%M%S")
    with open(regions_file, "w") as regions:
        regions.write("[SOURCE]\n")
        regions.write("region = " + source_region + "\n")
        regions.write("[DESTINATION]\n")
        regions.write("region = " + destination_region + "\n")
    return regions_file

def print_cmd():
    command = sys.argv[0]
    arguments = sys.argv[1:]
    logging.info(f"Executing the following command {command} with arguments {arguments}")

def config_logging(current_directory,base_config_file_name):
    logfilename = current_directory + "/logs/cold_disaster_recovery_" + base_config_file_name + ".log"
    logging.basicConfig(
        handlers=[
            logging.FileHandler(logfilename,'a'),
            logging.StreamHandler()
        ],
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )
    return logfilename

def read_config_file(config_file_name):
    # Opening JSON file
    config_file = open(config_file_name)

    # returns JSON object as a dictionary
    data = json.load(config_file)

    # Closing file
    config_file.close()
    return data

def update_config_file(config_file_name,data):
    # Opening JSON file
    with open(config_file_name, 'w') as file:
        json.dump(data, file, indent=4, default=lambda obj: to_dict(obj))

    # Closing file
    file.close()
    return 1

def get_db_system_details(db_system_id,oci_db_system_client):
    try:
        # Initialize the DB System client and fetch DB system details
        oci_db_system_details = oci_db_system_client.get_db_system(db_system_id)
        return oci_db_system_details
    except Exception as err:
        logging.error(f"{err}")
        return None

#LS NSG START
def get_vcn_id_from_subnet(oci_config, subnet_id, signer=None):
    network_client = oci.core.VirtualNetworkClient(oci_config, signer=signer)
    subnet = network_client.get_subnet(subnet_id).data
    return subnet.vcn_id, subnet.compartment_id

def find_nsg_id_by_name(network_client, compartment_id, vcn_id, display_name):
    """
    List NSGs in the compartment and VCN, return OCID if the display_name matches, else None.
    """
    nsgs = network_client.list_network_security_groups(
        compartment_id=compartment_id,
        vcn_id=vcn_id
    ).data
    for nsg in nsgs:
        if nsg.display_name == display_name:
            return nsg.id
    return None

def create_network_security_group(network_client, compartment_id, vcn_id, display_name):
    details = oci.core.models.CreateNetworkSecurityGroupDetails(
        compartment_id=compartment_id,
        vcn_id=vcn_id,
        display_name=display_name
    )
    nsg = network_client.create_network_security_group(details).data
    return nsg.id

def clean_none(d):
    """Recursively remove all keys with None values."""
    if isinstance(d, dict):
        return {k: clean_none(v) for k, v in d.items() if v is not None}
    return d

def nsg_rule_from_dict(rule, direction):
    direction = direction.lower()
    protocol = rule['protocol']
    proto_dict = {'protocol': protocol}
    if rule.get('description'):
        proto_dict['description'] = rule.get('description')
    if direction == "ingress":
        proto_dict['source'] = rule['source']
        proto_dict['source_type'] = rule['source_type']
    elif direction == "egress":
        proto_dict['destination'] = rule['destination']
        proto_dict['destination_type'] = rule['destination_type']
    else:
        raise ValueError(f"Unknown direction for rule: '{direction}'")
    # Clean all option objects of None, FULLY recursively!
    for opt in ['tcp_options', 'udp_options', 'icmp_options']:
        if rule.get(opt) is not None:
            cleaned = clean_none(rule[opt])
            if cleaned:  # will be an empty dict if all values were None
                proto_dict[opt] = cleaned
    return proto_dict


def log_nsg_rules(network_client, nsg_id, tag):
    """Fetch and log NSG rules nicely formatted."""
    try:
        rules = network_client.list_network_security_group_security_rules(nsg_id).data
        readable = json.dumps([to_dict(rule) for rule in rules], indent=2)
        logging.info(f"{tag} NSG rules for {nsg_id}:\n{readable}")
    except Exception as e:
        logging.error(f"Could not fetch NSG rules after {tag}: {str(e)}")

def build_oci_ingress(rule):
    kwargs = dict(
        direction="INGRESS",
        protocol=rule['protocol'],
        source=rule['source'],
        source_type=rule['source_type']
    )

    # TCP options
    if 'tcp_options' in rule and rule['tcp_options']:
        tcp_opts = rule['tcp_options']
        tcp_model = oci.core.models.TcpOptions()
        if 'destination_port_range' in tcp_opts and tcp_opts['destination_port_range']:
            pr = tcp_opts['destination_port_range']
            tcp_model.destination_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        if 'source_port_range' in tcp_opts and tcp_opts['source_port_range']:
            pr = tcp_opts['source_port_range']
            tcp_model.source_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        kwargs['tcp_options'] = tcp_model

    # UDP options
    if 'udp_options' in rule and rule['udp_options']:
        udp_opts = rule['udp_options']
        udp_model = oci.core.models.UdpOptions()
        if 'destination_port_range' in udp_opts and udp_opts['destination_port_range']:
            pr = udp_opts['destination_port_range']
            udp_model.destination_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        if 'source_port_range' in udp_opts and udp_opts['source_port_range']:
            pr = udp_opts['source_port_range']
            udp_model.source_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        kwargs['udp_options'] = udp_model

    # ICMP options
    if 'icmp_options' in rule and rule['icmp_options']:
        icmp_opts = rule['icmp_options']
        icmp_model = oci.core.models.IcmpOptions()
        if 'type' in icmp_opts and icmp_opts['type'] is not None:
            icmp_model.type = icmp_opts['type']
        if 'code' in icmp_opts and icmp_opts['code'] is not None:
            icmp_model.code = icmp_opts['code']
        kwargs['icmp_options'] = icmp_model

    return oci.core.models.AddSecurityRuleDetails(**kwargs)

def build_oci_egress(rule):
    kwargs = dict(
        direction="EGRESS",
        protocol=rule['protocol'],
        destination=rule['destination'],
        destination_type=rule['destination_type']
    )
    # TCP port only if present
    if 'tcp_options' in rule and rule['tcp_options']:
        tcp_opts = rule['tcp_options']
        tcp_model = oci.core.models.TcpOptions()
        if 'destination_port_range' in tcp_opts and tcp_opts['destination_port_range']:
            pr = tcp_opts['destination_port_range']
            tcp_model.destination_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        if 'source_port_range' in tcp_opts and tcp_opts['source_port_range']:
            pr = tcp_opts['source_port_range']
            tcp_model.source_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        kwargs['tcp_options'] = tcp_model
    #UDP 
    if 'udp_options' in rule and rule['udp_options']:
        udp_opts = rule['udp_options']
        udp_model = oci.core.models.UdpOptions()
        if 'destination_port_range' in udp_opts and udp_opts['destination_port_range']:
            pr = udp_opts['destination_port_range']
            udp_model.destination_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        if 'source_port_range' in udp_opts and udp_opts['source_port_range']:
            pr = udp_opts['source_port_range']
            udp_model.source_port_range = oci.core.models.PortRange(
                min=pr['min'],
                max=pr['max']
            )
        kwargs['udp_options'] = udp_model
    # ICMP
    if 'icmp_options' in rule and rule['icmp_options']:
        icmp_opts = rule['icmp_options']
        icmp_model = oci.core.models.IcmpOptions()
        if 'type' in icmp_opts and icmp_opts['type'] is not None:
            icmp_model.type = icmp_opts['type']
        if 'code' in icmp_opts and icmp_opts['code'] is not None:
            icmp_model.code = icmp_opts['code']
        kwargs['icmp_options'] = icmp_model

    return oci.core.models.AddSecurityRuleDetails(**kwargs)

def add_only_new_nsg_rules(network_client, nsg_id, ingress_rules, egress_rules):
    logging.info(f"Entering add_only_new_nsg_rules function with nsg_id: {nsg_id}")
    log_nsg_rules(network_client, nsg_id, tag='(Existing)')

    # Get current rules
    try:
        existing_rules = network_client.list_network_security_group_security_rules(nsg_id).data
    except Exception as e:
        logging.error(f"Failed to fetch existing NSG rules: {e}")
        return

    # Build lists of new (unique) rules
    new_ingress = []
    for rule in ingress_rules:
        found = any(
            r.direction == "INGRESS" and rule_equals(r, rule, "INGRESS")
            for r in existing_rules
        )
        if not found:
            new_ingress.append(rule)

    new_egress = []
    for rule in egress_rules:
        found = any(
            r.direction == "EGRESS" and rule_equals(r, rule, "EGRESS")
            for r in existing_rules
        )
        if not found:
            new_egress.append(rule)

    ingress_rule_dicts = [to_dict(rule) for rule in new_ingress]
    logging.info("new ingress rules for NSG ID %s:\n%s", nsg_id, json.dumps(ingress_rule_dicts, indent=2))

    # Add new ingress rules if any
    if new_ingress:
        for rule in new_ingress:
            rule_obj = build_oci_ingress(rule)
            ingress_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                security_rules=[rule_obj]
            )
            try:
                response = network_client.add_network_security_group_security_rules(nsg_id, ingress_details)
                logging.info(f"Add ingress response (raw) from OCI: {response.data}")
            except Exception as e:
                logging.error(f"Failed to add new ingress rules: {e}")

    # Add new egress rules if any
    if new_egress:
        for rule in new_egress:
            rule_obj = build_oci_egress(rule)
            egress_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                security_rules=[rule_obj]
            )
            try:
                response = network_client.add_network_security_group_security_rules(nsg_id, egress_details)
                logging.info(f"Add egress response (raw) from OCI: {response.data}")
            except Exception as e:
                logging.error(f"Failed to add new egress rules: {e}")

    log_nsg_rules(network_client, nsg_id, tag='(AFTER ADD)')
    logging.info("Exiting add_only_new_nsg_rules function")

def rule_equals(existing_rule, rule_dict, direction):
    """
    Compares an existing OCI rule object (from list_network_security_group_security_rules)
    with a rule_dict (from JSON), for the specified direction ('INGRESS' or 'EGRESS').

    Returns True if they match, else False.
    """
    # Normalize direction
    dir_norm = direction.lower()
    # Basic protocol match (must match exactly)
    # existing_rule.protocol could be '6' (for TCP), or 'all', etc.
    if str(existing_rule.protocol).lower() != str(rule_dict['protocol']).lower():
        return False
    # Direction itself
    if existing_rule.direction.lower() != dir_norm:
        return False
    # Source/Destination
    if dir_norm == 'ingress':
        if (getattr(existing_rule, 'source', None) != rule_dict.get('source') or
                getattr(existing_rule, 'source_type', None) != rule_dict.get('source_type')):
            return False
    else:  # egress
        if (getattr(existing_rule, 'destination', None) != rule_dict.get('destination') or
                getattr(existing_rule, 'destination_type', None) != rule_dict.get('destination_type')):
            return False
    # Optional fields: tcp_options, udp_options, icmp_options
    for field in ['tcp_options', 'udp_options', 'icmp_options']:
        # Input might be None or a dict
        # Existing_rule has attributes, sometimes None or with fields
        expected = rule_dict.get(field)
        actual = getattr(existing_rule, field, None)
        # To compare simply (conservatively), treat None == None
        if expected is None and actual is None:
            continue
        # If just 1 is None, that's a difference
        if expected is None or actual is None:
            return False
        # Else, compare values (convert both to dict)
        if isinstance(actual, dict):
            actual_dict = actual
        else:
            # Use OCI util to_dict if available
            try:
                from oci.util import to_dict
                actual_dict = to_dict(actual)
            except Exception:
                actual_dict = {k: v for k, v in actual.__dict__.items()}
        if expected != actual_dict:
            return False
    return True

# if __name__ == "__main__":
    oci_signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    oci_src_region = "ap-mumbai-1"
    oci_dst_region = "ap-hyderabad-1"
    current_directory = os.path.dirname(os.path.abspath(__file__))
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    base_config_file_name = os.path.basename("/config/demo-psql01.json").split('.')[0]
    regions_file = prepare_regions_file(oci_src_region,oci_dst_region,current_directory,base_config_file_name,script_name)
    config_logging(current_directory, base_config_file_name) 
    oci_dst_config = oci.config.from_file(file_location=regions_file, profile_name="DESTINATION")
    dst_network_client = oci.core.VirtualNetworkClient(oci_dst_config, signer=oci_signer)
    oci_dst_subnet_id = "ocid1.subnet.oc1.ap-hyderabad-1.aaaaaaaa5ysjas2tw4svxuhpwz3wy4oij3uhaasffr6aegronvofzli6ilsa"
    
    dst_vcn_id, dst_compartment_id = get_vcn_id_from_subnet(oci_dst_config, oci_dst_subnet_id, signer=oci_signer)
    
    standby_nsg_rules = [
    {
        "id": "ocid1.networksecuritygroup.oc1.ap-mumbai-1.aaaaaaaarxjxlcvytbttxqnxfxeqw4xxynbpzdawj3f24wo4b736fbazto3q",
        "display_name": "standby_db-nsg",
        "ingress_rules": [
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 5432,
                        "min": 5432
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 8010,
                        "min": 8009
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 8080,
                        "min": 8080
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 5432,
                        "min": 5432
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 22,
                        "min": 22
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 3000,
                        "min": 3000
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 8585,
                        "min": 8585
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 5000,
                        "min": 5000
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 8000,
                        "min": 8000
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            },
            {
                "protocol": "6",
                "source": "172.16.0.32/27",
                "source_type": "CIDR_BLOCK",
                "tcp_options": {
                    "destination_port_range": {
                        "max": 80,
                        "min": 80
                    },
                    "source_port_range": None
                },
                "udp_options": None,
                "icmp_options": None
            }
        ],
        "egress_rules": [
            {
                "protocol": "all",
                "destination": "0.0.0.0/0",
                "destination_type": "CIDR_BLOCK",
                "tcp_options": None,
                "udp_options": None,
                "icmp_options": None
            }
        ]
    }
    ]

    for nsg_def in standby_nsg_rules:
            nsg_display_name = nsg_def['display_name']
            ingress_rules = nsg_def.get('ingress_rules', [])
            egress_rules = nsg_def.get('egress_rules', [])
            
    nsg_id = find_nsg_id_by_name(dst_network_client, dst_compartment_id, dst_vcn_id, nsg_display_name)
    print(f"nsg_id : {nsg_id} ")

    add_only_new_nsg_rules(dst_network_client,nsg_id,ingress_rules,egress_rules)