#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import requests
from instance import *
from const import *
from obj.fmc_conf import *

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

        url = FMC_CONF.ip_addr + "/api/fmc_platform/v1/auth/generatetoken"

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
    def block_dest_ip(block_ip_addr):

        fmc_auth_resp = PyFMC.login()

        access_token = fmc_auth_resp.get('X-auth-access-token')
        refresh_token = fmc_auth_resp.get('X-auth-refresh-token')

        url = FMC_CONF.ip_addr + "/api/fmc_config/v1/domain/"+FMC_CONF.domain_uuid+"/policy/accesspolicies/000C2966-0C6A-0ed3-0000-519691043712/accessrules"

        headers = {'X-auth-access-token': access_token, 'X-auth-refresh-token': refresh_token}

        with open(BLOCK_IP_TMPL_PATH, "r") as jsonFile:
            data = json.load(jsonFile)

        data["destinationNetworks"]["literals"][0]["value"] = block_ip_addr
        data["name"] = block_ip_addr

        print(json.dumps(data))
        print(url)

        try:
            r = requests.post(url, headers=headers, data=json.dumps(data), verify=FMC_CONF.cer_loc)
            status_code = r.status_code
            resp = r.text
            print("Status code is: " + str(status_code))
            print("Post resp: " + str(resp))
            if status_code == 201 or status_code == 202:
                print("Post was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Error occurred in POST --> " + resp)
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r: r.close()

    @staticmethod
    def block_url(block_url_addr):

        fmc_auth_resp = PyFMC.login()

        access_token = fmc_auth_resp.get('X-auth-access-token')
        refresh_token = fmc_auth_resp.get('X-auth-refresh-token')

        url = FMC_CONF.ip_addr + "/api/fmc_config/v1/domain/"+FMC_CONF.domain_uuid+"/policy/accesspolicies/000C2966-0C6A-0ed3-0000-519691043712/accessrules"

        headers = {'X-auth-access-token': access_token, 'X-auth-refresh-token': refresh_token}

        with open(BLOCK_URL_TMPL_PATH, "r") as jsonFile:
            data = json.load(jsonFile)

        data["urls"]["literals"][0]["url"] = block_url_addr
        data["name"] = block_url_addr

        print(json.dumps(data))
        print(url)

        try:
            r = requests.post(url, headers=headers, data=json.dumps(data), verify=FMC_CONF.cer_loc)
            status_code = r.status_code
            resp = r.text
            print("Status code is: " + str(status_code))
            print("Post resp: " + str(resp))
            if status_code == 201 or status_code == 202:
                print("Post was successful...")
                json_resp = json.loads(resp)
                print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Error occurred in POST --> " + resp)
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r: r.close()


    @staticmethod
    def get_acpolicies():
        fmc_auth_resp = PyFMC.login()

        access_token = fmc_auth_resp.get('X-auth-access-token')
        refresh_token = fmc_auth_resp.get('X-auth-refresh-token')

        url = FMC_CONF.ip_addr + "/api/fmc_config/v1/domain/" + FMC_CONF.domain_uuid + "/policy/accesspolicies"

        headers = {'X-auth-access-token': access_token, 'X-auth-refresh-token': refresh_token}

        try:
            r = requests.get(url, headers=headers, verify=FMC_CONF.cer_loc)
            status_code = r.status_code
            resp = r.text
            print("Status code is: " + str(status_code))
            print("Post resp: " + str(resp))



            file_handler = open(ACPOLICIES_CONF_PILE_PATH, 'w')
            file_handler.write(resp)
            file_handler.close()

            with open(ACPOLICIES_CONF_PILE_PATH, 'r') as f:
                distros_dict = json.load(f)

            for distro in distros_dict:
                if distro['Name'] == "FTD5506":
                    print(distro)

            if status_code == 200 or status_code == 201 or status_code == 202:
                print("Post was successful...")
                json_resp = json.loads(resp)
                # print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                r.raise_for_status()
                print("Error occurred in POST --> " + resp)
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r: r.close()
