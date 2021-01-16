import json
import yaml
import logging
import traceback
import subprocess
import configparser
from common.const import CommonResult


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


def modify_yaml_config(yaml_path, section, key, value):
    with open(yaml_path) as f:
        doc = yaml.safe_load(f)

    doc[section][key] = value

    with open(yaml_path, 'w') as f:
        yaml.safe_dump(doc, f, default_flow_style=False)
