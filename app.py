#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyfmc import *
from const import *

def main():

    result = MISP_INSTANCE.get_all_attributes_txt('ip-dst', False, 64).text
    result2 = MISP_INSTANCE.get_all_attributes_txt('domain', False, 64).text
    result3 = MISP_INSTANCE.get_all_attributes_txt('domain', False, 64).text
    print(result, result2, result3)

    fmc_auth_resp = PyFMC.login()

    access_token = fmc_auth_resp.get('X-auth-access-token')
    refresh_token = fmc_auth_resp.get('X-auth-refresh-token')
    domain_uuid = fmc_auth_resp.get('DOMAIN_UUID')

    if access_token is not None and refresh_token is not None:
        print("Access token: %s" % access_token)
        print("Refresh token: %s" % refresh_token)
        print("DOMAIN UUID: %s\n" % domain_uuid)
    else:
        print("Response header is empty")

    fmc_conf = FmcConf()
    fmc_conf.acc_token = access_token
    fmc_conf.ref_token = refresh_token
    fmc_conf.domain_uuid = domain_uuid

    fmc_conf.write_to_file()


if __name__ == "__main__":
    main()