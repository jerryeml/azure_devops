import jmespath
import logging
from common.helper import AzureDevopsAPI
from common.const import CommonResult


def test():
    az_obj = AzureDevopsAPI()
    result = az_obj._get_deployment_group_agent(53)
    print(f"result: {result}")
    # length(value[?tags.status=='online'].id)
    # ?contains(@, 'foo') == `true`
    available_agent_count = jmespath.search("length(value[?contains(tags, 'available') == `true`].id)", result)
    print(available_agent_count)

    # az_obj._update_tags_of_deployment_group_agent()


if __name__ == "__main__":
    test()
