import argparse
import logging
import threading
import time
from common.winrm_util import PowerShell, LOG


def simple_useage():
    # Example for useage
    win_command = "whoami"
    # https://osce-vm.centralus.cloudapp.azure.com:5986
    p = PowerShell(username=u'trend', password=u'Osce@1234', target=u'https://one-16-int000.westus2.cloudapp.azure.com:5986', command=win_command)
    output = p.execute()
    LOG.info(output)


class MutiRunner:
    def __init__(self, user_name, user_pwd, target_fqdn_list, command):
        self.t_list = []
        self.user_name = user_name
        self.user_pwd = user_pwd
        self.target_fqdn_list = target_fqdn_list
        self.command = command

    def dosomething(self, i):
        LOG.info(f'No.{str(i)} Thread ID: {str(threading.get_ident())}, target is: {self.target_fqdn_list[int(i)]}')
        p = PowerShell(username=self.user_name, password=self.user_pwd, target=self.target_fqdn_list[int(i)], command=self.command)
        output = p.execute()
        LOG.info(output)

    def run(self):
        for i in range(len(self.target_fqdn_list)):
            self.t_list.append(threading.Thread(target=self.dosomething, args=(str(i))))
            time.sleep(1)
            self.t_list[i].start()

        for i in self.t_list:
            i.join()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # simple_useage()
    parser = argparse.ArgumentParser()
    parser.add_argument("-fqdn", dest="target_fqdn_list", type=str, required=True)
    parser.add_argument("-user", dest="user_name", type=str, required=True)
    parser.add_argument("-pwd", dest="user_pwd", type=str, required=True)
    parser.add_argument("-command", dest="command", type=str, required=False, default="whoami; ipconfig")
    args = parser.parse_args()

    t_job_list = args.target_fqdn_list.replace(' ', '').split(',')
    d = MutiRunner(user_name=args.user_name, user_pwd=args.user_pwd, target_fqdn_list=t_job_list, command=args.command)
    d.run()
