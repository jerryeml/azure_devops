import os
import sys
import argparse
import logging
import logging.handlers
import jmespath
import subprocess
from common.winrm_util import PowerShell
from common.helper import AzureDevopsAPI, AzureCLI, load_global_params_config, generate_random_prefix
from common.const import CommonResult


class MonitorResourceUtil(object):
    def __init__(self, username, az_pat, sp_client_id, sp_pwd, tenant_id, env_and_product):
        self.set_logger()
        self.username = username
        self.az_pat = az_pat
        self.sp_client_id = sp_client_id
        self.sp_pwd = sp_pwd
        self.tenant_id = tenant_id
        self.env_and_product = env_and_product
        self.env = self.env_and_product.split('-')[0]
        self.product = self.env_and_product.split('-')[1]
        self.vg_id, self.dg_id = self.get_params()
        self.prefix = generate_random_prefix()
        self.az_api = AzureDevopsAPI(self.username, self.az_pat)
        self.az_cli = AzureCLI(self.sp_client_id, self.az_pat, self.sp_pwd, self.tenant_id)

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
        result = self.az_api._get_deployment_group_agent(self.dg_id)
        # print(f"result: {result}")
        available_agent_count = jmespath.search("length(value[?contains(tags, 'available') == `true`].agent[?status == 'online'].id)", result)
        if available_agent_count < 4:
            logging.info(f"available agent count: {available_agent_count} is less than 4, do provision")
            is_provision = True
        else:
            logging.warning(f"available agent count: {available_agent_count}, no need provision")
            is_provision = False

        self.az_cli.update_var_in_variable_group(self.vg_id, f"{self.env_and_product}-provision", is_provision)

    def update_tags_of_dg_agent(self):
        """
        update avaiable tags to running
        only update win10/win16 at one time
        """
        result = self.az_api._get_deployment_group_agent(self.dg_id)
        available_agent = jmespath.search("value[?contains(tags, 'available') == `true`].{id: agent.id, name: agent.name, tags: tags}", result)

        available_agent_win10 = jmespath.search("[?contains(name, 'win10') == `true`].{id: id, name: name, tags: tags}", available_agent)
        available_agent_win16 = jmespath.search("[?contains(name, 'win16') == `true`].{id: id, name: name, tags: tags}", available_agent)

        if len(available_agent_win10) == 0 or len(available_agent_win16) == 0:
            logging.warning(f"Available win10 agent count: {len(available_agent_win10)}")
            logging.warning(f"Available win16 agent count: {len(available_agent_win16)}")
            return

        # update first agent tags >> available to running
        available_agent_win10[0]['tags'] = ['running' if tag.lower() == 'available' else tag for tag in available_agent_win10[0]['tags']]
        available_agent_win16[0]['tags'] = ['running' if tag.lower() == 'available' else tag for tag in available_agent_win16[0]['tags']]

        payload = [available_agent_win10[0], available_agent_win16[0]]
        logging.debug(f"payload: {payload}")
        self.az_api._update_tags_of_deployment_group_agent(self.vg_id, payload)

    def remove_deployment_group_agent(self):
        """
        unregister the dga
        """
        result = self.az_api._get_deployment_group_agent(self.dg_id)
        print(result)
        # running_agents = jmespath.search("value[?contains(tags, 'running') == `true`].{id: agent.id, name: agent.name, tags: tags}", result)

        # for agent in running_agents:
        #     tmp = agent['name']
        #     print(tmp)
        #     win_command = 'whoami'
        #     p = PowerShell(username=u'trend', password=u'Osce@1234', target=f'https://{tmp}.westus2.cloudapp.azure.com:5986', command=win_command)
        #     output = p.execute()
        #     print(output)

    def list_resource_in_lab(self):
        pass

    def del_resource_in_lab(self):
        lab_name = f'dtl-{self.env}-{self.product}'
        lab_rg_name = load_global_params_config()['azure_devops']['lab_rg_name']
        get_vms_name = self.az_cli.list_vm_in_dtl(lab_name, lab_rg_name, "[].name")
        logging.info(f'vm name: {get_vms_name}')
        # az_cli.del_vm_in_dtl()

    def test(self):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-user", dest="username", type=str, required=True)
    parser.add_argument("-pat", dest="az_pat", type=str, required=True)
    parser.add_argument("-sp-client-id", dest="sp_client_id", type=str, required=True)
    parser.add_argument("-sp-pwd", dest="sp_pwd", type=str, required=True)
    parser.add_argument("-tenant-id", dest="tenant_id", type=str, required=True)
    parser.add_argument("-env-product", dest="env_and_product", type=str, required=True)
    parser.add_argument("-a", dest="action", type=str, required=False, default="nothing")
    args = parser.parse_args()

    o = MonitorResourceUtil(username=args.username,
                            az_pat=args.az_pat,
                            sp_client_id=args.sp_client_id,
                            sp_pwd=args.sp_pwd,
                            tenant_id=args.tenant_id,
                            env_and_product=args.env_and_product)
    if args.action.lower() == 'monitor':
        o.monitor_resource_in_lab()
    elif args.action.lower() == '':
        pass
    else:
        pass
