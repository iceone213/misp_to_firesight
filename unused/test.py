#!/usr/bin/env python

from obj.fmc_conf import *
from obj.misp_conf import *

def main():

    misp_conf = MispConf()
    print(misp_conf.to_json())

    # misp_conf.ver_cert = False
    # misp_conf.write_to_file()
    # print(misp_conf.to_json())

    # print()

    # fmc_conf = FmcConf()
    # print(fmc_conf.to_json())

    # fmc_conf.login = "stat"
    # fmc_conf.password = "TestPass"
    # fmc_conf.write_to_file()
    # print(fmc_conf.to_json())


if __name__ == "__main__":
    main()
