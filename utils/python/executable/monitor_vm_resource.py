import jmespath
import logging
from common.helper import AzureDevopsAPI, load_global_params_config, deploy_command_return_result
from common.const import CommonResult


def monitor_vm_resource_in_lab(username="jerry_he@trendmicro.com", az_pat="hr3p34bhv3bsmjah6gjrr63gqbcrtznq7fzqvedo2r7k6z457eja"):
    az_obj = AzureDevopsAPI(username, az_pat)
    result = az_obj._get_deployment_group_agent(load_global_params_config()["azure_devops"]["one_int_deployment_group_id"])
    # print(f"result: {result}")
    available_agent_count = jmespath.search("length(value[?contains(tags, 'available') == `true`].id)", result)
    print(available_agent_count)

    if available_agent_count < 4:
        print(f"available agent count: {available_agent_count} is less than 4, do provision")
        deploy_command_return_result(command=f'echo "##vso[task.setvariable variable=available_agent_count]{available_agent_count}"')
    else:
        print(f"available agent count: {available_agent_count}, no need provision")


if __name__ == "__main__":
    monitor_vm_resource_in_lab()
