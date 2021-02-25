import os

from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from dotenv import load_dotenv

load_dotenv(dotenv_path='env')


personal_access_token = os.getenv('PERSONAL_ACCESS_TOKEN')
organization_url = os.getenv('ORGANIZATION_URL')
project = os.getenv('PROJECT')


class TestRunnerPoolNotFound(Exception):
    pass


class TestMachinePoolNotFound(Exception):
    pass


class AgentBasePool:
    def __init__(self, root_project=None):
        credentials = BasicAuthentication('', personal_access_token)
        connection = Connection(base_url=organization_url, creds=credentials)
        self._project = root_project
        self.client = connection.clients_v6_0.get_task_agent_client()

    def _get_groups(self, group_name):
        try:
            groups = self.client.get_deployment_groups(project)
            for group in groups:
                if group.name == group_name:
                    return group
            return groups
        except TestRunnerPoolNotFound:
            print(f"Unable to find pool: {group_name}")


class TestRunnerPool(AgentBasePool):
    def __init__(self, root_project):
        super().__init__(root_project)

    def test_runners(self, pool_name):
        group = self._get_groups(pool_name)
        return self.client.get_deployment_targets(self._project, group.id)


class TestMachinePool(AgentBasePool):
    def __init__(self, root_project):
        super().__init__(root_project)

    def _find_pool_id_by_name(self, name):
        try:
            pools = self.client.get_agent_pools(name)
            for pool in pools:
                if pool.name == name:
                    return pool.id
            return pools
        except TestMachinePoolNotFound:
            print(f"Unable to find pool: {name}")

    def test_machines(self, pool_name):
        pool_id = self._find_pool_id_by_name(pool_name)
        return self.client.get_agents(pool_id)


if __name__ == '__main__':
    test_runners = TestRunnerPool(project).test_runners("v1-epp-testrunner-agents")
    machines = TestMachinePool(project).test_machines("ONE")

    test_runner = iter(test_runners)
    machine = iter(machines)
    test_runner_maps = list(zip(test_runner, machine))

    for i, test_runner_map in enumerate(test_runner_maps, 1):
        test_runner = test_runner_map[0]
        print(f"{i} - {test_runner.agent.name} {test_runner.tags}")
        machine = test_runner_map[1]
        print(f"{i} - {machine.name} {machine.os_description} {machine.user_capabilities}")

