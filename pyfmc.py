#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import requests
from obj.fmc_conf import *
from const import *

class PyFMC:

    @staticmethod
    def auth_request(url, headers, cert_loc):

        if url.startswith("https"):
            try:
                resp = requests.post(url, headers=headers, verify=cert_loc)
                if resp is None:
                    raise ValueError("Response is undefined")
                if resp.status_code != 204:
                    msg = "Error Status Code: %d in response" % resp.status_code
                    raise ValueError(msg)
            except Exception as e:
                raise e
        else:
            resp = requests.post(url, headers=headers)

        return resp

    @staticmethod
    def logout(access_token):

        url = FmcConf().ip_addr + "/api/fmc_platform/v1/auth/revokeaccess"

        headers = {'X-auth-access-token': access_token}

        try:
            auth_request(url, headers, FMC_CONF.cert_loc)
        except Exception as e:
            raise e

        return 0

    @staticmethod
    def login():

        url = FmcConf().ip_addr + "/api/fmc_platform/v1/auth/generatetoken"

        base64string = base64.encodebytes((FMC_CONF.login + ":" + FMC_CONF.password).encode()).decode().rstrip()
        authstring = ("Basic %s" % base64string)
        headers = {'Authorization': authstring}

        try:
            resp = requests.post(url, headers=headers, verify=FMC_CONF.cer_loc)
            if resp is None:
                raise ValueError("Response is undefined")
            if resp.status_code != 204:
                msg = "Error Status Code: %d in response" % resp.status_code
                raise ValueError(msg)
        except Exception as e:
            raise e

        return {'X-auth-access-token': resp.headers['X-auth-access-token'], 'X-auth-refresh-token': resp.headers['X-auth-refresh-token'],
                'DOMAIN_UUID': resp.headers['DOMAIN_UUID']}

    @staticmethod
    def add_acl_rule():

        url = FMC_CONF.ip_addr + "/api/fmc_config/v1/domain/"+FMC_CONF.domain_uuid+"/policy/accesspolicies/000C2966-0C6A-0ed3-0000-519691043712/accessrules"

        base64string = base64.encodebytes((FMC_CONF.login + ":" + FMC_CONF.password).encode()).decode().rstrip()
        authstring = ("Basic %s" % base64string)

        headers = {'Authorization': authstring, 'X-auth-access-token': FMC_CONF.acc_token, 'X-auth-refresh-token': FMC_CONF.ref_token}

        try:
            resp = requests.post(url, headers=headers, verify=FMC_CONF.cer_loc)
            if resp is None:
                raise ValueError("Response is undefined")
            if resp.status_code != 204:
                msg = "Error Status Code: %d in response" % resp.status_code
                raise ValueError(msg)
        except Exception as e:
            raise e

        resp.json()

        return {'X-auth-access-token': resp.headers['X-auth-access-token'],
                'X-auth-refresh-token': resp.headers['X-auth-refresh-token'],
                'DOMAIN_UUID': resp.headers['DOMAIN_UUID']}