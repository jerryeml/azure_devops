import logging
import os
import shlex
import subprocess
import sys
import time
import yaml


def _get_pre_execution(product_name: str, testing_scope: str, feature_folder=None) -> list:
    cmds = None
    common_config_path = os.path.join(CASES_FOLDER, product_name, 'common_config.yml')
    custom_config_path = os.path.join(PROJECT_FOLDER, feature_folder, 'custom_config.yml')

    if os.path.exists(custom_config_path):
        logging.info(f"custom config path: {custom_config_path}")
        with open(custom_config_path) as steam:
            custom_config = yaml.safe_load(steam)
        if custom_config['testing_service'][f"env_{testing_scope}"]['individual']:
            if 'pre_execution' in custom_config['testing_service'][f'env_{testing_scope}']:
                cmds = custom_config['testing_service'][f'env_{testing_scope}']['pre_execution']

    if cmds is None:
        with open(common_config_path) as steam:
            common_config = yaml.safe_load(steam)

        if 'pre_execution' in common_config['testing_service'][f'env_{testing_scope}']:
            cmds = common_config['testing_service'][f"env_{testing_scope}"]['pre_execution']

    logging.info(f"get pre-execution cmds: {cmds}")
    return cmds


def _run_pre_execution(cmds: list):
    logger = logging.getLogger('pre_execution')
    is_success = True
    for cmd in cmds:
        exe_p = None
        try:
            # Running subprocess should extend the sqs timeout, otherwise the task will expired.
            exe_p = _run_subprocess(cmd, logger)

            if exe_p.returncode != 0:
                logger.error(f"Run {cmd} failed")
                raise RuntimeError("Run command failed")

            logger.info(f"Run {cmd} successfully")
        except Exception as e:
            logger.info(f"Child process object content:\n{exe_p}")
            logger.exception(e)
            is_success = False
            break
    return is_success


def _run_subprocess(cmd: str, logger: object):
    cmd_list = shlex.split(cmd)
    logger.info("Run command -> %s", cmd_list)
    proc = subprocess.Popen(cmd_list, cwd=PROJECT_FOLDER, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    timeout_count = 0
    while proc.poll() is None:
        time.sleep(1)
        timeout_count += 1

        # Default timeout after 900 sec (15 min). raise timeout
        if timeout_count >= 900:
            proc.terminate()
            raise RuntimeError(f"Calling subprocess timeout with cmd {cmd_list}")

    try:
        logger.info("Subprocess return code: [%s]", proc.returncode)
        logger.info("Subprocess Stderr:\n%s", proc.stdout.read().decode())
        logger.info("Subprocess Stderr:\n%s", proc.stderr.read().decode())
    except Exception:
        pass

    return proc


def main():
    # Run robot only when no pre-execution cmds or pre-execution cmds finished successfully
    cmds = _get_pre_execution(product_name, testing_scope, feature_file)
    is_pre_execution_success = True
    if cmds:
        is_pre_execution_success = _run_pre_execution(cmds)

    if not is_pre_execution_success:
        logging.error('Running execution failed!')


if __name__ == '__main__':
    task_data = sys.argv[1]

    product_name = task_data['product_name']
    testing_scope = task_data['testing_scope']
    feature_file = task_data['feature_file']

    CASES_FOLDER = task_data['CASES_FOLDER']
    PROJECT_FOLDER = task_data['PROJECT_FOLDER']

    main()
