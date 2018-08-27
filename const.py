#!/usr/bin/env python

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FMC_CONF_FILE_PATH = './json/fmc_conf.json'
MISP_CONF_FILE_PATH = './json/misp_conf.json'
ACPOLICIES_CONF_PILE_PATH = './json/acpolicies_conf.json'

BLOCK_IP_TMPL_PATH = "./tmpl/block_dest_ip.json"
BLOCK_URL_TMPL_PATH = "./tmpl/block_url.json"
DEPLOY_VER_TMPL_PATH = "./tmpl/deploy_ver.json"
POLICY_ASSIGN_TMPL_PATH = "./tmpl/policy_assign_1.json"

