import base64
import requests
from pymisp import PyMISP
from const import *

def init():
    return PyMISP(MISP_SRV, MISP_API_KEY, MISP_VERCERT, 'json')


def auth_request(url, headers, cert_loc):

    api_path = "/api/fmc_platform/v1/auth/generatetoken"
    url = fmc_server + api_path

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



def logout(access_token):
    headers = {'X-auth-access-token': access_token}

    try:
        auth_request(url, headers, cert_loc)
    except Exception as e:
        raise e

    return 0

def login():

    base64string = base64.encodebytes((FMC_USER + ":" +FMC_PASS).encode()).decode().rstrip()
    authstring = ("Basic %s" % base64string)
    print(authstring)
    headers = {'Authorization': authstring}

    try:
        resp = requests.post(FMC_AUTH_URL, headers=headers, verify=FMC_CERT_LOC)
        if resp is None:
            raise ValueError("Response is undefined")
        if resp.status_code != 204:
            msg = "Error Status Code: %d in response" % resp.status_code
            raise ValueError(msg)
    except Exception as e:
        raise e

    return {'X-auth-access-token': resp.headers['X-auth-access-token'], 'X-auth-refresh-token': resp.headers['X-auth-refresh-token']}


def main():

    # misp = init()

    result = MISP_INSTANCE.get_all_attributes_txt('ip-dst', False, 64).text
    result2 = MISP_INSTANCE.get_all_attributes_txt('domain', False, 64).text
    result3 = MISP_INSTANCE.get_all_attributes_txt('domain', False, 64).text

    print(result, result2, result3)

    result = login()

    access_token = result.get('X-auth-access-token')
    refresh_token = result.get('X-auth-refresh-token')
    if access_token is not None and refresh_token is not None:
        print("\nAccess tokens and Refresh tokens exist.")
        print("Access token: %s" % access_token)
        print("Refresh token: %s\n" % refresh_token)
        # result_logout = logout(result['X-auth-access-token'])
        # print("Logout Results: %d" % result_logout)
    else:
        print("Access tokens and refresh tokens does not exist.")


# Stand Alone execution
if __name__ == "__main__":
    main()