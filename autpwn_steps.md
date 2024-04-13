# Steps for validation autopwn

- Abuse second order sqli injection and write a php file to get rce.
- Abuse the rce to connect back and get a shell.
- Pop user flag in /home/htb.
- Search root password inside the php.config file and get access to root.
- Pop root flag in /root directory.
