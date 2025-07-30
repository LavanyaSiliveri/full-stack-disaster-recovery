import oci
import argparse
import os
import sys
import logging
from datetime import timezone
import datetime
import psql_utils

# Argument Parsing
# This section parses the command-line arguments for the script.
parser = argparse.ArgumentParser(description='Test NSG backup')
parser.add_argument("-c", "--config-file", required=True, help="Specify the JSON configuration file.")
parser.add_argument("-t", "--timeout", help="Specify the maximum time to wait, in seconds. Defaults to 1200 seconds.", type=int, default=1200)
args = parser.parse_args()

# Extract parsed arguments
config_file_name = args.config_file
oci_max_wait_seconds = args.timeout

# For generating the Regions file for the authentication
# Get the current directory of the script and the script name
current_directory = os.path.dirname(os.path.abspath(__file__))
script_name = os.path.splitext(os.path.basename(__file__))[0]
# Get the base name of the config ficurrent directory of the script
base_config_file_name = os.path.basename(config_file_name).split('.')[0]

# Configure logging
logfilename = psql_utils.config_logging(current_directory,base_config_file_name)

logging.info(args)

def test_nsg_bkp():
    data = psql_utils.read_config_file(config_file_name)

    oci_src_region = data["psql_db_details"]["primary_region"]
    oci_dst_region = data["psql_db_details"]["standby_region"]

    # regions_file = psql_utils.prepare_regions_file(oci_src_region,oci_dst_region,current_directory,base_config_file_name,script_name)
    
    oci_signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    oci_src_config = oci.config.from_file("~/.oci/config ", profile_name="DEFAULT")
    oci_standby_config = oci.config.from_file("~/.oci/config ", profile_name="STANDBY")
    

    primary_subnet_id = data["psql_db_details"]["primary_subnet_id"]
    standby_subnet_id = data["psql_db_details"]["standby_subnet_id"]
    standby_network_client = oci.core.VirtualNetworkClient(config=oci_standby_config, signer=oci_signer)
    standby_subnet = standby_network_client.get_subnet(subnet_id=data["psql_db_details"]["standby_subnet_id"]).data
    standby_subnet_cidr = standby_subnet.cidr_block

    primary_network_client = oci.core.VirtualNetworkClient(config=oci_src_config, signer=oci_signer)
    primary_subnet = primary_network_client.get_subnet(subnet_id=primary_subnet_id).data

    primary_nsg_ids = primary_subnet.nsg_ids

    primary_nsg_rules = []
    for nsg_id in primary_nsg_ids:
        primary_nsg = primary_network_client.get_network_security_group(network_security_group_id=nsg_id).data
        primary_nsg_rules.append({
            "id": nsg_id,
            "display_name": primary_nsg.display_name,
            "ingress_rules": [],
            "egress_rules": []
        })
        for rule in primary_network_client.list_network_security_group_security_rules(network_security_group_id=nsg_id).data:
            if rule.direction == "INGRESS":
                primary_nsg_rules[-1]["ingress_rules"].append({
                    "protocol": rule.protocol,
                    "source": rule.source,
                    "source_type": rule.source_type,
                    "tcp_options": rule.tcp_options,
                    "udp_options": rule.udp_options,
                    "icmp_options": rule.icmp_options
                })
            else:
                primary_nsg_rules[-1]["egress_rules"].append({
                    "protocol": rule.protocol,
                    "destination": rule.destination,
                    "destination_type": rule.destination_type,
                    "tcp_options": rule.tcp_options,
                    "udp_options": rule.udp_options,
                    "icmp_options": rule.icmp_options
                })
    data["psql_db_details"]["primary_nsg_rules"] = primary_nsg_rules
    data["psql_db_details"]["standby_nsg_rules"] = primary_nsg_rules
    
    # Update display_name for standby_nsg_rules
    for rule in data["psql_db_details"]["standby_nsg_rules"]:
        rule["display_name"] = "standby_" + rule["display_name"]
        for ingress_rule in rule["ingress_rules"]:
            if ingress_rule["source_type"] == "CIDR_BLOCK":
                ingress_rule["source"] = standby_subnet_cidr
        
    
    update_file = psql_utils.update_config_file(config_file_name,data)

if __name__ == "__main__":
    psql_utils.print_cmd()
    test_nsg_bkp()