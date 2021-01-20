import os
import sys
import argparse
import logging
import logging.handlers
import jmespath
import subprocess
from common.helper import AzureDevopsAPI, AzureCLI, load_global_params_config
from common.const import CommonResult


def setLogger():
    logFile = os.path.join(os.path.dirname(__file__), r'{}.log'.format(__file__))
    logFormatter = '%(asctime)s [%(levelname)s] [%(funcName)s] %(message)s - [%(filename)s(%(lineno)s)]'
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    format = logging.Formatter(logFormatter)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(format)
    log.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(logFile, maxBytes=(1048576 * 5), backupCount=7)
    fh.setFormatter(format)
    log.addHandler(fh)


def monitor_vm_resource_in_lab(username, az_pat, sp_client_id, sp_pwd, tenant_id):
    az_api = AzureDevopsAPI(username, az_pat)
    result = az_api._get_deployment_group_agent(load_global_params_config()["azure_devops"]["one_int_deployment_group_id"])
    # print(f"result: {result}")
    available_agent_count = jmespath.search("length(value[?contains(tags, 'available') == `true`].id)", result)

    if available_agent_count < 4:
        logging.info(f"available agent count: {available_agent_count} is less than 4, do provision")
        az_cli = AzureCLI(sp_client_id, sp_pwd, tenant_id)
        az_cli.update_var_in_variable_group(3, "available_agent_count", available_agent_count)
    else:
        logging.warning(f"available agent count: {available_agent_count}, no need provision")


if __name__ == "__main__":
    setLogger()
    logging.info("================================ Start ================================")
    parser = argparse.ArgumentParser()
    parser.add_argument("-user", dest="username", type=str, required=True)
    parser.add_argument("-pat", dest="az_pat", type=str, required=True)
    parser.add_argument("-sp-client-id", dest="sp_client_id", type=str, required=True)
    parser.add_argument("-sp-pwd", dest="sp_pwd", type=str, required=True)
    parser.add_argument("-tenant-id", dest="tenant_id", type=str, required=True)
    args = parser.parse_args()

    monitor_vm_resource_in_lab(username=args.username,
                               az_pat=args.az_pat,
                               sp_client_id=args.sp_client_id,
                               sp_pwd=args.sp_pwd,
                               tenant_id=args.tenant_id)
