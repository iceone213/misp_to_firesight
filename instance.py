#!/usr/bin/env python

from obj.misp_conf import *
from obj.fmc_conf import *
from pymisp import PyMISP

MISP_CONF = MispConf()
FMC_CONF = FmcConf()

MISP_INSTANCE = PyMISP(MISP_CONF.ip_addr, MISP_CONF.api_token, MISP_CONF.ver_cert, 'json')