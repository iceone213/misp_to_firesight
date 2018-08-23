#!/usr/bin/env python

import json

class FmcConf:

    FMC_CONF_FILE_PATH = './json/fmc_conf.json'

    def __init__(self):
        self.read_from_file()

    def to_json(self):
        return json.dumps(self.__dict__)

    def write_to_file(self):
        with open(self.FMC_CONF_FILE_PATH, 'w') as outfile:
            json.dump(self.__dict__, outfile)

    def read_from_file(self):
        j = json.load(open(self.FMC_CONF_FILE_PATH))

        self.ip_addr = j['ip_addr']
        self.login = j['login']
        self.password = j['password']
        self.cer_loc = j['cer_loc']
        self.acpolicy_id = j['acpolicy_id']
        self.acpolicy_name = j['acpolicy_name']
        self.acc_token = j['acc_token']
        self.ref_token = j['ref_token']
        self.domain_uuid = j['domain_uuid']