import logging
from common import helper
from common.const import CommonResult


def list_cliamable_vms_in_lab():
    command = "az lab vm list --lab-name dtl-int --resource-group rg-testing-env-lab --query \"length([])\" --claimable"
    result = helper.deploy_command_return_result(command)
    return result


def monitor_cliamable_vms_in_each_labs():
    claimable_vm_count = list_cliamable_vms_in_lab()
    if int(claimable_vm_count) < 4:
        logging.warning(f"claimable resource:{claimable_vm_count} less than 4, do provision")
        return CommonResult.need_to_provision
    logging.info(f"claimable resource:{claimable_vm_count} more than 4, do not provision")
    return CommonResult.no_need_to_provision


if __name__ == "__main__":
    print(monitor_cliamable_vms_in_each_labs())
