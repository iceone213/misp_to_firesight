#!/usr/bin/env python

from const import *
import json

class MispConf:

    def __init__(self):
        self.read_from_file()

    def to_json(self):
        return json.dumps(self.__dict__)

    def write_to_file(self):
        with open(MISP_CONF_FILE_PATH, 'w') as outfile:
            json.dump(self.__dict__, outfile)

    def read_from_file(self):
        j = json.load(open(MISP_CONF_FILE_PATH))

        self.ip_addr = j['ip_addr']
        self.api_token = j['api_token']
        self.ver_cert = j['ver_cert']