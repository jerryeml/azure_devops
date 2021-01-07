import logging
import time
import uuid
import xml.etree.ElementTree as ElementTree
from base64 import b64encode
from xml.etree.ElementTree import ParseError

import requests
import winrm
import xmltodict
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
from retry import retry
from winrm import Session
from winrm.exceptions import InvalidCredentialsError
from winrm.exceptions import WinRMError
from winrm.exceptions import WinRMOperationTimeoutError
from winrm.exceptions import WinRMTransportError
from winrm.protocol import Protocol

from exception import OSCETaskError
from exception import OSCEWinRMCommandTimeout
from exception import OSCEWinRMOperationTimeout
from exception import OSCEWinRMIllegalOperation
from exception import OSCEWinRMClassNotRegister
from exception import OSCEWinRMTransportException

"""
Support Python3.6
If you want to use in py3, you have to add "return session" in winrm folder and script transport.py after line 293
"""


LOG = logging.getLogger(__name__)


def parse_error_response(xml):
    """Parsing SOAP XML returned from WinRM
    Args:
        xml (str): XML formatted str

    Returns:
        err_code (str): WinRM error code
        err_msg (str): WinRM error msg
    """
    ns = {'e': 'http://www.w3.org/2003/05/soap-envelope',
          'f': 'http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'}
    try:
        root = ElementTree.fromstring(xml)
    except (ParseError, TypeError) as ex:
        LOG.error('parsing response SOAP XML failed: %s', ex)
        return None, None

    found_element = root
    xml_tags = ['e:Body', 'e:Fault', 'e:Reason', 'e:Text']  # look for err message
    for t in xml_tags:
        if found_element is not None:  # must use "is not None" to check, please see python document
            found_element = found_element.find(t, ns)
    err_msg = found_element.text if found_element is not None else None

    xml_tags = ['e:Body', 'e:Fault', 'e:Detail', 'f:WSManFault']  # look for err code
    found_element = root
    for t in xml_tags:
        if found_element is not None:
            found_element = found_element.find(t, ns)

    err_code = found_element.get('Code', None) if found_element is not None else None

    return err_code, err_msg


def fix_send_message(self, message):
    """Hacking from winrm.transport.Transport.send_message
    For adding detailed error message
    """
    if not self.session:
        self.session = self.build_session()

    # urllib3 fails on SSL retries with unicode buffers- must send it a byte string
    # see https://github.com/shazow/urllib3/issues/717
    if isinstance(message, type(u'')):
        message = message.encode('utf-8')

    request = requests.Request('POST', self.endpoint, data=message)
    prepared_request = self.session.prepare_request(request)

    try:
        response = self.session.send(prepared_request, timeout=self.read_timeout_sec)
        response_text = response.text
        response.raise_for_status()
        return response_text
    except requests.HTTPError as ex:
        if ex.response.status_code == 401:
            raise InvalidCredentialsError("the specified credentials were rejected by the server")
        if ex.response.content:
            response_text = ex.response.content
        else:
            response_text = ''
        # Per http://msdn.microsoft.com/en-us/library/cc251676.aspx rule 3,
        # should handle this 500 error and retry receiving command output.
        if b'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive' in message and b'Code="2150858793"' in response_text:
            LOG.debug('Receiving cmd result from %s but exceed operation timeout, keep retry', ex.request.url)
            raise WinRMOperationTimeoutError()

        # hack start
        # 2150858793 Operation timeout
        # 2147943418 Illegal operation attempted on a registry key that has been marked for deletion.
        # 2147746132 Class not registered
        LOG.error('Send message [%s] to [%s] get HTTP code [%s] [%s]', message, self.endpoint, ex.response.status_code, response_text)
        err_code, err_msg = parse_error_response(response_text)
        if err_code == "2150858793":
            # raise EPASWinRMOperationTimeout(err_msg)
            raise OSCEWinRMOperationTimeout(err_msg)
        elif err_code == "2147943418":
            # raise EPASWinRMIllegalOperation(err_msg)
            raise OSCEWinRMIllegalOperation(err_msg)
        elif err_code == "2147746132":
            # raise EPASWinRMClassNotRegister(err_msg)
            raise OSCEWinRMClassNotRegister(err_msg)
        else:
            # raise EPASWinRMTransportException(ex.response.status_code, err_code, err_msg)
            raise OSCEWinRMTransportException(ex.response.status_code, err_code, err_msg)
        # hack end


winrm.transport.Transport.send_message = fix_send_message


class CustomProtocol(Protocol):
    """Custom WinRM signal protocol.

    It overrides the function get_command_output and add a new function ctrlc_command.
    """
    def __init__(self, *args, command_timeout_sec=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.command_timeout_sec = command_timeout_sec

    def ctrlc_command(self, shell_id, command_id):
        """Send ctrl-c to the remote command.

        This method is copied from cleanup_command(). The only difference is that it sends the signal ctrl_c.
        """
        message_id = uuid.uuid4()
        req = {'env:Envelope': self._get_soap_header(
            resource_uri='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd',
            action='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
            shell_id=shell_id,
            message_id=message_id)}

        # Signal the Command references to terminate (close stdout/stderr)
        signal = req['env:Envelope'].setdefault(
            'env:Body', {}).setdefault('rsp:Signal', {})
        signal['@CommandId'] = command_id
        signal['rsp:Code'] = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c'

        res = self.send_message(xmltodict.unparse(req))
        root = ElementTree.fromstring(res)
        relates_to = next(
            node for node in root.findall('.//*')
            if node.tag.endswith('RelatesTo')).text
        # TODO change assert into user-friendly exception
        assert uuid.UUID(relates_to.replace('uuid:', '')) == message_id

    def get_command_output(self, shell_id, command_id):
        """
        Get the Output of the given shell and command
        @param string shell_id: The shell id on the remote machine.
         See #open_shell
        @param string command_id: The command id on the remote machine.
         See #run_command
        #@return [Hash] Returns a Hash with a key :exitcode and :data.
         Data is an Array of Hashes where the cooresponding key
        #   is either :stdout or :stderr.  The reason it is in an Array so so
         we can get the output in the order it ocurrs on
        #   the console.
        """
        stdout_buffer, stderr_buffer = [], []
        command_done = False

        start_time = time.time()
        while not command_done:
            try:
                stdout, stderr, return_code, command_done = self._raw_get_command_output(shell_id, command_id)
                stdout_buffer.append(stdout)
                stderr_buffer.append(stderr)
            except WinRMOperationTimeoutError as _:
                # this is an expected error when waiting for a long-running process, just silently retry
                pass
            finally:
                if self.command_timeout_sec > 0 and (time.time() - start_time) > self.command_timeout_sec:
                    self.ctrlc_command(shell_id, command_id)
                    # raise EPASWinRMCommandTimeout(self.command_timeout_sec)
                    raise OSCEWinRMCommandTimeout(self.command_timeout_sec)

        return b''.join(stdout_buffer), b''.join(stderr_buffer), return_code


class CustomSession(Session):
    def __init__(self, *args, auth, command_timeout_sec=0, **kwargs):
        super().__init__(*args, auth, **kwargs)
        username, password = auth
        self.protocol = CustomProtocol(self.url, command_timeout_sec=command_timeout_sec, username=username, password=password, **kwargs)


class WinCmd(object):  # TaskBase
    """to execute cmd in remote Windows host via WinRM protocol
    Args:
        target: host to connect with e.g. https://trend.com.tw
        command: windows command to run
        username  Windows login username
        password:  Windows login password
        read_timeout_sec: raw socket read timeout, get passed to requests package, must be greater than operation timeout
        operation_timeout_sec: winrm protocol timeout, when timeout, WinRMOperationTimeoutError will be raised internally
        command_timeout_sec: longest time to waiting for complete of execution commands, 0 is no timeout
    Attributes:
        _winrm_session (CustomSession): pywinrm session obj
    """

    def __init__(self, target, username, password, command,
                 conn_retry=2,
                 read_timeout_sec=250,  # read timeout must be greater than operation timeout
                 operation_timeout_sec=200,
                 command_timeout_sec=0,  # 0 means no timeout
                 transport='ntlm',
                 **kwargs):
        super().__init__(**kwargs)

        self._target = target
        self._command = command

        self._winrm_session = CustomSession(self._target,
                                            auth=(username, password),
                                            read_timeout_sec=read_timeout_sec,  # pywinrm default is 30
                                            operation_timeout_sec=operation_timeout_sec,  # pywinrm default is 20
                                            command_timeout_sec=command_timeout_sec,
                                            server_cert_validation='ignore',
                                            transport=transport)

        # pywinrm uses requests library to send HTTP request
        # so using its HTTPAdapter to setup connection retry count
        requests_session = self._winrm_session.protocol.transport.session
        if requests_session is None:
            requests_session = self._winrm_session.protocol.transport.build_session()
            self._winrm_session.protocol.transport.session = requests_session

        # requests.sessions.Session has default https/http adapter with 0 retry
        # here mount the adapters with new retry value to override default adapters
        requests_session.mount('https://', HTTPAdapter(max_retries=conn_retry))
        requests_session.mount('http://', HTTPAdapter(max_retries=conn_retry))

    # @retry((EPASWinRMOperationTimeout, EPASWinRMIllegalOperation, EPASWinRMClassNotRegister), tries=3, delay=10, logger=LOG)
    @retry((OSCEWinRMOperationTimeout, OSCEWinRMIllegalOperation, OSCEWinRMClassNotRegister), tries=3, delay=10, logger=LOG)
    def command_execute(self, command):
        LOG.debug(command)
        return self._winrm_session.run_cmd(command)

    def execute(self):
        """Execute the task

        Returns:
            dict that has code/std_out/std_err/err_msg keys
        """

        return_dict = {'code': 0, 'std_out': None, 'std_err': None, 'err_msg': None}

        try:
            result = self.command_execute(self._command)
        except (OSCEWinRMTransportException, WinRMError, WinRMTransportError, WinRMOperationTimeoutError, RequestException) as ex:
            # pywinrm does not handle requests.exceptions.ConnectionError in transport.py line 184
            # it handles HTTPError only
            err_str = 'execute command in %s error: [%s] %s with error code: %s' % (self._target, type(ex), ex, ex.code if hasattr(ex, 'code') else None)
            LOG.error(err_str)
            # raise EPASTaskError(err_str)
            raise OSCETaskError(err_str)
        else:
            return_dict['code'] = result.status_code
            return_dict['std_out'] = result.std_out
            return_dict['std_err'] = result.std_err

        return return_dict


class PowerShell(WinCmd):
    """to execute powershell script in remote host via WinRM protocol
    """

    # @retry((EPASWinRMOperationTimeout, EPASWinRMIllegalOperation, EPASWinRMClassNotRegister), tries=3, delay=10, logger=LOG)
    @retry((OSCEWinRMOperationTimeout, OSCEWinRMIllegalOperation, OSCEWinRMClassNotRegister), tries=3, delay=10, logger=LOG)
    def command_execute(self, command):
        """Execute powershell script"""
        LOG.debug('Executing command: %s', command)
        # Adding SilentlyContinue for $ProgressPreference
        # suppress the std err like: 'Preparing modules for first use.'
        return self._run_ps('$ProgressPreference = "SilentlyContinue";' + command)

    def _run_ps(self, script):
        """fixed version of run_ps() from original winrm package
        std_err have to be decoded by utf-8
        """
        encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
        rs = self._winrm_session.run_cmd('powershell -NoProfile -encodedcommand {0}'.format(encoded_ps))
        if len(rs.std_err):
            # pylint: disable=W0212
            rs.std_err = self._winrm_session._clean_error_msg(rs.std_err.decode('utf-8'))  # fix: adding utf-8 decode
        return rs


def for_useage():
    # Example for useage
    win_command = 'whoami'
    # https://osce-vm.centralus.cloudapp.azure.com:5986
    p = PowerShell(username=u'trend', password=u'Osce@1234', target=u'https://vm-test000.westus2.cloudapp.azure.com:5986', command=win_command)
    p.execute()
    print(p.execute())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    for_useage()
