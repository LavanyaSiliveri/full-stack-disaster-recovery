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

def nsg_rule_from_dict(rule, direction):
    protocol = rule['protocol']
    proto_dict = {
        'protocol': protocol,
        'description': rule.get('description', None)
    }
    if direction == "ingress":
        proto_dict.update({
            'source': rule['source'],
            'source_type': rule['source_type']
        })
    else:
        proto_dict.update({
            'destination': rule['destination'],
            'destination_type': rule['destination_type']
        })
    for opt in ['tcp_options', 'udp_options', 'icmp_options']:
        if rule.get(opt) is not None:
            proto_dict[opt] = rule.get(opt)
    return proto_dict

def add_nsg_rules(network_client, nsg_id, ingress_rules, egress_rules):
    if ingress_rules:
        ingress_objs = [
            oci.core.models.AddNetworkSecurityGroupSecurityRulesDetailsSecurityRulesItem(
                direction="INGRESS", **nsg_rule_from_dict(rule, "ingress")
            )
            for rule in ingress_rules
        ]
        ingress_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(security_rules=ingress_objs)
        network_client.add_network_security_group_security_rules(nsg_id, ingress_details)

    if egress_rules:
        egress_objs = [
            oci.core.models.AddNetworkSecurityGroupSecurityRulesDetailsSecurityRulesItem(
                direction="EGRESS", **nsg_rule_from_dict(rule, "egress")
            )
            for rule in egress_rules
        ]
        egress_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(security_rules=egress_objs)
        network_client.add_network_security_group_security_rules(nsg_id, egress_details)
#LS NSG END