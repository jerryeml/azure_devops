import os

from azure.devops.connection import Connection
from azure.devops.v6_0.release.models import ReleaseStartMetadata
from azure.devops.v6_0.release.models import ConfigurationVariableValue
from msrest.authentication import BasicAuthentication
from dotenv import load_dotenv

load_dotenv(dotenv_path='env')

personal_access_token = os.getenv('PERSONAL_ACCESS_TOKEN')
organization_url = os.getenv('ORGANIZATION_URL')
project = os.getenv('PROJECT')


class ReleasePipelineNotFound(Exception):
    pass


class RunReleasePipeline:
    def __init__(self):
        credentials = BasicAuthentication('', personal_access_token)
        connection = Connection(base_url=organization_url, creds=credentials)
        self.release_client = connection.clients_v6_0.get_release_client()

    def _find_definition_id(self, name):
        try:
            definitions = self.release_client.get_release_definitions(project)
            for definition in definitions:
                if definition.name == name:
                    return definition.id
        except ReleasePipelineNotFound:
            print(f"Unable to find definition id by {name}")

    def run_release_pipeline(self, name, variables=None, is_draft=False, artifacts=None, ):
        release_start_metadata = ReleaseStartMetadata(
            definition_id=self._find_definition_id(name),
            is_draft=is_draft,
            artifacts=artifacts,
            variables=variables.variables)
        self.release_client.create_release(release_start_metadata, project)


class ReleaseVariableGroup:
    def __init__(self):
        self._variables = dict()

    def set(self, name, value, allow_override=False, is_secret=False):
        self._variables[name] = ConfigurationVariableValue(allow_override=allow_override, is_secret=is_secret, value=value)

    @property
    def variables(self):
        return self._variables


if __name__ == '__main__':
    variables = ReleaseVariableGroup()
    variables.set("app_name", "VisionOne")
    variables.set("l2_version", "1.0.0")
    variables.set("app_version", "2.0.1")
    variables.set("task_number", "5")
    variables.set("l2_case_repo", "data-l2-testing-case")
    variables.set("cd_region", "westus2")
    variables.set("cd_region_code", "westus2")
    RunReleasePipeline().run_release_pipeline('Run L2 Test Case', variables)
    print("Run Release Pipeline for Run L2 Test Case")
