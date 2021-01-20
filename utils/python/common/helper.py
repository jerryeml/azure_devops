import os
import json
import yaml
import requests
import logging
import traceback
import subprocess
import configparser
from os.path import dirname
from requests.auth import HTTPBasicAuth
from common.const import CommonResult


def load_global_params_config(py_root_path=dirname(dirname(__file__))):
    config_path = os.path.join(py_root_path,
                               "global_params.yaml")
    with open(config_path) as f:
        global_params = yaml.load(f.read(), Loader=yaml.SafeLoader)

    logging.info(f"loading global params config: {config_path}")
    return global_params


def deploy_command_no_return_result(command=None):
    """
    Use az command to delpoy service and get the result back
    :param command: az command, reference: https://docs.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest
    @return: 0 success; 1 fail
    """

    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    process.wait()
    if process.returncode != 0:
        logging.error(f"process return code: {process.returncode}")
        raise subprocess.CalledProcessError(process.returncode, command)

    return CommonResult.Success


def deploy_command_return_result(command=None):
    """
    Use az command to delpoy service and get the result back
    :param command: az command, reference: https://docs.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest
    @return: list type of command result
    """

    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    return_code = process.communicate(input=None)[0]
    process.wait()
    # logging.debug("Retunr value: %s, type: %s", return_code, type(return_code))  # type str
    if process.returncode != 0:
        logging.error(f"process return code: {process.returncode}, return result: {return_code}")
        raise subprocess.CalledProcessError(process.returncode, command)

    transform_json = json.loads(return_code)
    return transform_json


def verfiy_value_from_dict(target_dict, verify_key_name, expect_value, default=2):
    """
    find the value in dict or json (support dict in list, support string)
    @return value if the target is found; if not found will return 2; 1 means fail
    """
    logging.debug("Input type is: %s", type(target_dict))
    if target_dict == expect_value:
        return expect_value
    if isinstance(target_dict, (dict)):
        for key in target_dict:
            logging.debug("Now verify key: %s", key)
            if expect_value == target_dict[key]:
                if verify_key_name == key:
                    return expect_value
            else:
                if isinstance(target_dict[key], (dict)):
                    refind_value = verfiy_value_from_dict(target_dict[key], verify_key_name, expect_value, default)
                    if refind_value is not default:
                        return refind_value
        logging.warning("Value: %s Not Found in dict: %s, Return: %s", expect_value, target_dict, default)
        return default
    elif isinstance(target_dict, (list)):
        for each in target_dict:
            refind_value = verfiy_value_from_dict(each, verify_key_name, expect_value, default)
            if refind_value is not default:
                return refind_value
    else:
        logging.error("input: %s, target_dict type: %s is not correct", target_dict, type(target_dict))
        return CommonResult.Fail


def load_ini_object(ini_path):
    config = configparser.ConfigParser()
    config.read(ini_path)
    return config


def load_value_from_ini(ini_path, section, key):
    config_object = load_ini_object(ini_path)
    config_object.read(ini_path)
    value = config_object.get(section, key)
    return value


def load_yaml_config(yaml_path):
    with open(yaml_path) as f:
        yaml_config = yaml.load(f.read(), Loader=yaml.SafeLoader)

    logging.info(f"loading global params config: {yaml_config}")
    return yaml_config


def modify_yaml_config(yaml_path, section, key, value):
    with open(yaml_path) as f:
        doc = yaml.safe_load(f)

    doc[section][key] = value

    with open(yaml_path, 'w') as f:
        yaml.safe_dump(doc, f, default_flow_style=False)


class AzureDevopsAPI(object):
    def __init__(self, username, az_pat):
        self.username = username
        self.az_pat = az_pat
        self.organization = load_global_params_config()['azure_devops']['org']
        self.project = load_global_params_config()['azure_devops']['project']

    def _get_deployment_group_agent(self, deployment_group_id):
        url = "https://dev.azure.com/{organization}/{project}/_apis/distributedtask/deploymentgroups/{deploymentGroupId}/targets/?api-version=6.0-preview.1".format(organization=self.organization,
                                                                                                                                                                    project=self.project,
                                                                                                                                                                    deploymentGroupId=deployment_group_id)
        response = requests.get(url, auth=HTTPBasicAuth(self.username, self.az_pat))
        logging.info("response status_code: {}".format(response.status_code))
        assert response.status_code == 200
        return response.json()

    def _del_deployment_group_agent(self, target_id, deployment_group_id):
        url = "https://dev.azure.com/{organization}/{project}/_apis/distributedtask/deploymentgroups/{deploymentGroupId}/targets/{targetId}?api-version=6.0-preview.1".format(organization=self.organization,
                                                                                                                                                                              project=self.project,
                                                                                                                                                                              deploymentGroupId=deployment_group_id,
                                                                                                                                                                              targetId=target_id)
        response = requests.delete(url, auth=HTTPBasicAuth(self.username, self.az_pat))
        logging.info("delete agnet in deployment group status_code: {}".format(response.status_code))
        assert response.status_code == 200 or response.status_code == 204
        return CommonResult.Success

    def _update_tags_of_deployment_group_agent(self):
        deploymentGroupId = 53
        organization = "infinite-wars"
        project = "v1-epp-saas-1.0"
        url = f"https://dev.azure.com/{organization}/{project}/_apis/distributedtask/deploymentgroups/{deploymentGroupId}/targets?api-version=6.0-preview.1"
        payload = [{
            "tags": [
                "db",
                "web",
                "newTag5248232320667898861"
            ],
            "id": 82
        },
            {
            "tags": [
                "db",
                "newTag5248232320667898861"
            ],
            "id": 83
        }
        ]
        response = requests.patch(url, json=payload, auth=HTTPBasicAuth(self.username, self.az_pat))
        print(response)


class AzureCLI(object):
    def __init__(self, username, az_pat, sp_pwd, tenant_id):
        self.username = username
        self.az_pat = az_pat
        self.sp_pwd = sp_pwd
        self.tenant_id = tenant_id
        self._install_az_extension()
        self.az_login()

    def _install_az_extension(self):
        command = f'az extension add --name "azure-devops"'
        install_result = deploy_command_no_return_result(command=command)
        assert install_result == 0

    def az_login(self):
        command = f"az login --service-principal --username {self.username} --password {self.sp_pwd} --tenant {self.tenant_id}"
        login_result = deploy_command_no_return_result(command=command)
        assert login_result == 0

    def az_devops_login(self):
        command = f'set AZURE_DEVOPS_EXT_PAT="{self.az_pat}"; az devops login'
        login_result = deploy_command_no_return_result(command=command)
        assert login_result == 0

    def update_var_in_variable_group(self, deployment_group_id, key, value):
        org = os.path.join(load_global_params_config()['azure_devops']['url'], load_global_params_config()['azure_devops']['org'])
        project = load_global_params_config()['azure_devops']['project']
        command = f"az pipelines variable-group variable update --org {org} --project {project} --id {deployment_group_id} --name {key} --value {value}"
        try:
            update_result = deploy_command_no_return_result(command=command)
            assert update_result is 0
        except subprocess.CalledProcessError as e:
            logging.warning(e)
            command = f"az pipelines variable-group variable create --org {org} --project {project} --id {deployment_group_id} --name {key} --value {value}"
            create_result = deploy_command_no_return_result(command=command)
            assert create_result is 0
