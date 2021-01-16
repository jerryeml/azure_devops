import argparse
import os
import subprocess
import sys
import time
import urllib.request
import zipfile
import winreg
from pathlib import Path


def parse_argument():
    parser = argparse.ArgumentParser(description="To skip some step")
    parser.add_argument('--skip-pip', dest="skip_pip", action='store_true')
    parser.add_argument('--skip-env-path', dest="skip_env_path", action='store_true')
    parser.set_defaults(skip_pip=False)
    parser.set_defaults(skip_env_path=False)
    arg = parser.parse_args()
    return arg


arg = parse_argument()


def insert_environment_path(root_path):
    if not arg.skip_env_path:
        utility_path = [r'utility\webdriver']
        utility_path = list(map(lambda x: os.path.join(root_path, x), utility_path))
        python_package_root_path = os.path.join(root_path, r'utils\python')
        insert_variable_path('PATH', utility_path)
        insert_variable_path('PYTHONPATH', [root_path, python_package_root_path])


def insert_variable_path(path_name, added_paths):
    path = os.environ.get(path_name)
    if not path:
        path = ''
    for i in added_paths:
        if i not in path:
            print(f'Add {i} into {path_name}.')
            path += ';{}'.format(i) if path else '{}'.format(i)
    path = path.replace('"', '')
    command = 'setx /M {} "{}"'.format(path_name, path)
    print(f'Command is going to be executed: {command}')
    subprocess.call(command)


def do_pip_install(root_path):
    if not arg.skip_pip:
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', '-r', os.path.join(root_path, 'requirements.txt')])


def download_chromedriver():
    latest_driver_version = _get_latest_chromedriver_version()
    download_url = f'https://chromedriver.storage.googleapis.com/{latest_driver_version}/chromedriver_win32.zip'
    _download_webdriver(download_url)


def _download_webdriver(download_url):
    current_folder = Path(__file__).parent
    zipfile_name = os.path.basename(download_url)
    zipfile_path = current_folder / zipfile_name
    unzip_dst_folder = current_folder / 'utility' / 'webdriver'

    if os.path.exists(zipfile_path):
        os.unlink(zipfile_path)

    print(f'Trying to download web driver zip...{download_url}')
    download_resp = urllib.request.urlopen(download_url)

    with open(zipfile_path, "wb") as local_file:
        local_file.write(download_resp.read())

    # wait download completed
    download_timeout = 120
    zip_file_size = os.path.getsize(zipfile_path)
    for timeout_i in range(download_timeout):
        print('Zip file {} size {}'.format(zipfile_path, zip_file_size))
        if zip_file_size == 0:
            print(f'Zip file size is 0, try to wait download complete...{timeout_i}')
            time.sleep(1)
        else:
            break
    else:
        raise Exception('Wait Download web file zip timeout')
    print('Download web driver zip file completed!')

    if zipfile.is_zipfile(zipfile_path):
        with zipfile.ZipFile(zipfile_path, 'r') as zip_ref:
            zip_ref.extractall(unzip_dst_folder)
        zipfile_path.unlink()
    else:
        dst_file_path = unzip_dst_folder / zipfile_name
        dst_file_path.unlink(missing_ok=True)
        zipfile_path.rename(dst_file_path)


def _get_latest_chromedriver_version():
    print('Trying to update latest driver version')
    url = r'https://chromedriver.storage.googleapis.com/LATEST_RELEASE'
    print('Check URL -> {}'.format(url))
    response = urllib.request.urlopen(url)
    print('Response: {}'.format(response))
    driver_version = response.read().strip().decode('utf-8')
    return driver_version


def _download_webdriver(download_url):
    current_folder = Path(__file__).parent
    zipfile_name = os.path.basename(download_url)
    zipfile_path = current_folder / zipfile_name
    unzip_dst_folder = current_folder / 'utility' / 'webdriver'

    if os.path.exists(zipfile_path):
        os.unlink(zipfile_path)

    print(f'Trying to download web driver zip...{download_url}')
    download_resp = urllib.request.urlopen(download_url)

    with open(zipfile_path, "wb") as local_file:
        local_file.write(download_resp.read())

    # wait download completed
    download_timeout = 120
    zip_file_size = os.path.getsize(zipfile_path)
    for timeout_i in range(download_timeout):
        print('Zip file {} size {}'.format(zipfile_path, zip_file_size))
        if zip_file_size == 0:
            print(f'Zip file size is 0, try to wait download complete...{timeout_i}')
            time.sleep(1)
        else:
            break
    else:
        raise Exception('Wait Download web file zip timeout')
    print('Download web driver zip file completed!')

    if zipfile.is_zipfile(zipfile_path):
        with zipfile.ZipFile(zipfile_path, 'r') as zip_ref:
            zip_ref.extractall(unzip_dst_folder)
        zipfile_path.unlink()
    else:
        dst_file_path = unzip_dst_folder / zipfile_name
        dst_file_path.unlink(missing_ok=True)
        zipfile_path.rename(dst_file_path)


if __name__ == '__main__':
    root = os.path.dirname(os.path.abspath(__file__)).replace('/', os.sep)
    try:
        print(f"root path:{root}")
        insert_environment_path(root)
        do_pip_install(root)
        for download_driver in [download_chromedriver]:
            try:
                download_driver()
            except Exception as e:
                print(f'Fail to {download_driver.__name__} due to exception: {e}')
    except Exception as e:
        print(e)
