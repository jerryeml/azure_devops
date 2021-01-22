import os
import sys
import argparse
import logging
import logging.handlers
import jmespath
import subprocess
from common.helper import AzureDevopsAPI, AzureCLI, load_global_params_config, generate_random_prefix
from common.const import CommonResult


class MonitorResource(object):
    def __init__(self, username, az_pat, sp_client_id, sp_pwd, tenant_id, env, product):
        self.set_logger()
        self.username = username
        self.az_pat = az_pat
        self.sp_client_id = sp_client_id
        self.sp_pwd = sp_pwd
        self.tenant_id = tenant_id
        self.env = env
        self.product = product
        self.vg_id, self.dg_id = self.get_params()
        self.prefix = generate_random_prefix()
        self.vm10_prefix = f'{self.product}-10{self.prefix}'
        self.vm16_prefix = f'{self.product}-16{self.prefix}'

    def set_logger(self):
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

    def get_params(self):
        if "int" in self.env:
            dg_id_int = f"dg_id_int_{self.product}"
            dg_id = load_global_params_config()["azure_devops"][dg_id_int]
        elif "dev" in self.env:
            dg_id_dev = f"dg_id_dev_{self.product}"
            dg_id = load_global_params_config()["azure_devops"][dg_id_dev]
        elif "stg" in self.env:
            dg_id_stg = f"dg_id_stg_{self.product}"
            dg_id = load_global_params_config()["azure_devops"][dg_id_stg]
        elif "prod" in self.env:
            dg_id_prod = f"dg_id_prod_{self.product}"
            dg_id = load_global_params_config()["azure_devops"][dg_id_prod]
        else:
            raise AssertionError(f"env:{self.env} is not supported")

        vg_id_product = f"vg_id_{self.product}"
        vg_id = load_global_params_config()["azure_devops"][vg_id_product]
        return vg_id, dg_id

    def monitor_resource_in_lab(self):
        az_api = AzureDevopsAPI(self.username, self.az_pat)
        result = az_api._get_deployment_group_agent(self.dg_id)
        # print(f"result: {result}")
        available_agent_count = jmespath.search("length(value[?contains(tags, 'available') == `true`].id)", result)

        if available_agent_count < 4:
            logging.info(f"available agent count: {available_agent_count} is less than 4, do provision")
            az_cli = AzureCLI(self.sp_client_id, self.az_pat, self.sp_pwd, self.tenant_id)
            az_cli.update_var_in_variable_group(self.vg_id, f"{self.env}_available_agent", available_agent_count)

            logging.info(f"generate machine prefix: {self.vm10_prefix}, {self.vm16_prefix}")
            az_cli.update_var_in_variable_group(self.vg_id, f"{self.env}_vm10_prefix", self.vm10_prefix)
            az_cli.update_var_in_variable_group(self.vg_id, f"{self.env}_vm16_prefix", self.vm16_prefix)
        else:
            logging.warning(f"available agent count: {available_agent_count}, no need provision")


if __name__ == "__main__":
    # setLogger()
    parser = argparse.ArgumentParser()
    parser.add_argument("-user", dest="username", type=str, required=True)
    parser.add_argument("-pat", dest="az_pat", type=str, required=True)
    parser.add_argument("-sp-client-id", dest="sp_client_id", type=str, required=True)
    parser.add_argument("-sp-pwd", dest="sp_pwd", type=str, required=True)
    parser.add_argument("-tenant-id", dest="tenant_id", type=str, required=True)
    parser.add_argument("-env", dest="env_name", type=str, required=True)
    parser.add_argument("-product", dest="product", type=str, required=True)
    args = parser.parse_args()

    MonitorResource(username=args.username,
                    az_pat=args.az_pat,
                    sp_client_id=args.sp_client_id,
                    sp_pwd=args.sp_pwd,
                    tenant_id=args.tenant_id,
                    env=args.env_name,
                    product=args.product).monitor_resource_in_lab()
