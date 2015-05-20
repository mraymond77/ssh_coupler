#!/usr/bin/env python
"""
Daemon for administratively coupling two ssh channels together. Currently
it only supports sftp. ssh_coupler.py requires that a user account exists on 
the base server (same server this daemon is running from) and that the base account
has a rsa key for authentication the final target account, whose name should be
identical. The username, hostname, port, and path to private key should be  
in the configuration file, ssh_coupler.conf. When an end user authenticates
as an account to this daemon, a client is stated and authenticates to the final
target server, and the payloads of the packets are interchanged. It will appear
to the user that they are simply connected to the base server, when it really is 
connected through to the end target server. 
"""

import logging
import optparse
import os
import pam
import socket
import sys
import textwrap
import traceback

import paramiko
from paramiko.common import DEBUG, INFO
from threading import Thread

HOST, PORT = '0.0.0.0', 2222
BACKLOG = 10
HOST_KEY = paramiko.RSAKey(filename='/etc/ssh/ssh_host_rsa_key')
PAM_AUTH = pam.pam()
_CONFIG = {}

log_name = 'ssh_coupler.main'
root_logger = paramiko.util.get_logger(log_name)

class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if PAM_AUTH.authenticate(username, password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        # Testing: all are allowed
        return paramiko.AUTH_SUCCESSFUL
        
    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

# overridden paramiko.SFTPServer __init__ and start_subsystem to enable packet interchange 
# between outer client and inner sshd. 
class MiddleManSFTPServer(paramiko.SFTPServer):
    def __init__(self, channel, name, server, *largs, **kwargs):
        self.client_addr = kwargs.pop('client_addr')
        self.transport = channel.get_transport()
        super(MiddleManSFTPServer, self).__init__(channel, name, server, *largs, **kwargs)

        self.dest_username = self.transport.get_username()
        self.dest_hostname = _CONFIG[self.dest_username][0]
        self.dest_port = _CONFIG[self.dest_username][1]
        self.privkey = paramiko.rsakey.RSAKey(filename=_CONFIG[self.dest_username][2])
        self.hostkeytype = None
        self.hostkey = None
        try:
            print(self.dest_username, self.dest_hostname, self.dest_port, self.privkey)
            self.host_keys = paramiko.util.load_host_keys(os.path.expanduser('/home/%s/.ssh/known_hosts' % self.transport.get_username()))
        except IOError:
            root_logger.log(INFO, '*** Unable to open host keys file')
            self.host_keys = {}
        if self.dest_hostname in self.host_keys:
            self.hostkeytype = self.host_keys[self.dest_hostname].keys()[0]
            self.hostkey = self.host_keys[self.dest_hostname][self.hostkeytype]
            root_logger.log(INFO, 'Using host key of type %s' % self.hostkeytype)
        try:
            self.client_transport = paramiko.Transport((self.dest_hostname, self.dest_port))
            self.client_transport.connect(self.hostkey, self.dest_username, pkey=self.privkey)
            self.inner_SFTPClient = paramiko.SFTPClient.from_transport(self.client_transport)
        except Exception as e:
            root_logger.log(INFO, '*** Caught exception: %s: %s' % (e.__class__, e))
            traceback.print_exc()
            try:
                self.client_transport.close()
            except:
                pass
            sys.exit(1)


    def cleanup(self):
        self._log(DEBUG, '%s: Closing associated SFTPClient connection.' % self.client_addr)
        self.inner_SFTPClient.close()
        self.inner_SFTPClient.sock.get_transport().close()
        self.finish_subsystem()
        self.transport.close()


    def start_subsystem(self, name, transport, channel):
        self.sock = channel
        self._log(INFO, '%s: Starting channel coupling' % (self.client_addr))
        self._send_server_version()
        while True:
            try:
                # source is connection between external client and the paramiko sftp server
                # dest is connection between paramiko sftp client and internal sshd
                source_t, source_data = self._read_packet()

            except EOFError:
                self._log(INFO, '%s: Server received EOF -- end of session' % self.client_addr)
                self.cleanup()
                return
            except Exception as e:
                self._log(DEBUG, 'Exception on channel: ' + str(e))
                self._log(DEBUG, paramiko.util.tb_strings())
                self.cleanup()
                return
            msg = paramiko.sftp.Message(source_data)
            request_number = msg.get_int()
            self._log(DEBUG, '%s: Request number: ' % self.client_addr + str(request_number))
            try:
                # cross wires between source ssh client and inner sshd 
                self.inner_SFTPClient._send_packet(source_t, source_data)
                dest_t, dest_data = self.inner_SFTPClient._read_packet()
                self._send_packet(dest_t, dest_data)
            except Exception as e:
                self._log(DEBUG, 'Exception in server processing: ' + str(e))
                self._log(DEBUG, paramiko.util.tb_strings())
                try:
                    self._send_status(request_number, paramiko.sftp.SFTP_FAILURE)
                except:
                    pass


def start_server(host, port, HOST_KEY, level):
    # Listen on socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    try:
        server_socket.bind((host, port))
    except socket.error, msg:
        root_logger.log(INFO, ' *** Socket bind failed. Error: ' + str(msg[0]) + ' Message: ' + msg[1])
        sys.exit(1)
    server_socket.listen(BACKLOG)
    root_logger.log(INFO, ' *** ssh_coupler.py listening on ' + host + ':' + str(port))

    while True:
        conn, addr = server_socket.accept()
        client_addr = addr[0] + ':' + str(addr[1])
        root_logger.log(INFO, "Connection Received from: " + str(client_addr))
        serv_transport = paramiko.Transport(conn)
        serv_transport.add_server_key(HOST_KEY)
        serv_transport.set_subsystem_handler('sftp', MiddleManSFTPServer, client_addr=client_addr)
        server = Server()
        try:
            serv_transport.start_server(server=server)
        except paramiko.SSHException:
            root_logger.log(INFO, ' *** SSH negotiation failed with %s' % addr[0])
            serv_transport.close()
            continue


def main():

    usage = """\
    usage: sftpserver [options]\
    """
    parser = optparse.OptionParser(usage=textwrap.dedent(usage))
    parser.add_option(
        '--host', dest='host', default=HOST,
        help='listen on HOST [default: %default]')
    parser.add_option(
        '-p', '--port', dest='port', type='int', default=PORT,
        help='listen on PORT [default: %default]'
        )
    parser.add_option(
        '-l', '--level', dest='level', default='INFO',
        help='Debug level: WARNING, INFO, DEBUG [default: %default]'
        )

    # Read config into active configuration
    options, args = parser.parse_args()

    paramiko_level = getattr(paramiko.common, options.level)
    paramiko.common.logging.basicConfig(level=paramiko_level)

    if os.path.isfile('/etc/ssh_coupler.conf'):
        with open('/etc/ssh_coupler.conf', 'r') as config_file:
            hosts = [line.rstrip() for line in config_file]
        hosts = [line.split() for line in hosts if line]
        for h in hosts:
            dest_username = h[0]
            dest_hostname = h[1]
            dest_port = int(h[2])
            dest_privkey = h[3]
            _CONFIG[dest_username] = [dest_hostname, dest_port, dest_privkey]
        print(_CONFIG)
    else:
        root_logger.log(INFO, '/etc/ssh_coupler.conf not found. Exiting')
        sys.exit(1)

    start_server(options.host, options.port, HOST_KEY, options.level)


if __name__ == '__main__':
    main()
