import logging
import os
import shlex
import subprocess
import sys
import time

from junitparser import JUnitXml


def _run_robot_test(feature_file, repo_name, testing_scope, ami_tag, testcase_name) -> bool:
    is_all_pass = True
    report_path = _get_robot_report_path(feature_file, testcase_name, ami_tag)
    robot_xml_path = os.path.join(report_path, "output.xml")
    robot_log_path = os.path.join(report_path, "log.html")
    robot_report_path = os.path.join(report_path, "report.html")
    robot_junit_path = os.path.join(report_path, "junit.xml")

    if ami_tag:
        case_name_args = f'-N "{testcase_name}-{ami_tag}"'
    else:
        case_name_args = f'-N "{testcase_name}"'

    tag = f"{repo_name}AND{testing_scope}"
    cmd = f'python -m robot -i {tag}' \
          f' -o "{robot_xml_path}" -l "{robot_log_path}" -r "{robot_report_path}"' \
          f' -x "{robot_junit_path}" -t "{testcase_name}" {case_name_args} {feature_file}'
    robot_process = None
    try:
        # Running subprocess should extend the sqs timeout, otherwise the task will expired.
        robot_process = _run_subprocess(cmd, logging)

        if robot_process.returncode != 0:
            raise RuntimeError("Run robot framework cases failed")

        if _check_fail_case_count(robot_junit_path) > 0:
            is_all_pass = False

    except Exception as e:
        is_all_pass = False
        logging.error("Run robot failed:")
        logging.exception(e)

    return is_all_pass


def _get_robot_report_path(feature: str, testcase_name: str, ami_tag: str):
    feature = feature.replace("cases/", "")
    report_path = os.path.join(PROJECT_FOLDER, 'reports', feature, testcase_name)
    if ami_tag:
        report_path = os.path.join(report_path, ami_tag)
    logging.info("Robot Report path -> [%s]", report_path)
    return report_path


def _run_subprocess(cmd: str, logger: object):
    cmd_list = shlex.split(cmd)
    logger.info("Run command -> %s", cmd_list)
    proc = subprocess.Popen(cmd_list, cwd=PROJECT_FOLDER, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    timeout_count = 0
    while proc.poll() is None:
        time.sleep(1)
        timeout_count += 1

        # Default timeout after 7200 sec (2 hr). raise timeout
        if timeout_count >= 7200:
            proc.terminate()
            raise RuntimeError(f"Calling subprocess timeout with cmd {cmd_list}")

    try:
        logger.info("Subprocess return code: [%s]", proc.returncode)
        logger.info("Subprocess Stderr:\n%s", proc.stdout.read().decode())
        logger.info("Subprocess Stderr:\n%s", proc.stderr.read().decode())
    except Exception:
        pass

    return proc


def _check_fail_case_count(junit_file_path):
    for i in range(30):
        if os.path.exists(junit_file_path):
            logging.info("File [%s] found!", junit_file_path)
            break
        time.sleep(1)
        logging.info("Wait for file present [%s]", i)
    else:
        logging.error("File not exists [%s]", junit_file_path)
        return 999

    xml = JUnitXml.fromfile(junit_file_path)
    return xml.failures


def main():
    logging.info(f'Run robot test cases {testcase_name}')
    is_all_pass = _run_robot_test(feature_file, repo_name, testing_scope, ami_tag, testcase_name)

    if not is_all_pass:
        logging.error('Running robot testcase failed!')


if __name__ == '__main__':
    task_data = sys.argv[1]

    testcase_name = task_data['testcase_name']

    testing_scope = task_data['testing_scope']
    feature_file = task_data['feature_file']
    repo_name = task_data['repo_name']
    ami_tag = task_data['ami_tag']

    PROJECT_FOLDER = task_data['PROJECT_FOLDER']

    main()
