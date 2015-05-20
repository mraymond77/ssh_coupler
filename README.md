# ssh_coupler
## Grants ability to administratively couple together two ssh channels.
### Dependancies
paramiko
pam-python
currently only supports python 2
### Run Down
ssh_coupler.py is a daemon for administratively coupling two ssh channels together. Currently it only supports sftp. ssh_coupler.py requires that a user account exists on the base server (same server this daemon is running from) and that the base account has a rsa key for authentication the final target account, whose name should be identical. The username, hostname, port, and path to private key should be in the configuration file, ssh_coupler.conf. When an end user authenticates as an account to this daemon, a client is stated and authenticates to the final target server, and the payloads of the packets are interchanged. It will appear to the user that they are simply connected to the base server, when it really is connected through to the end target server.`
