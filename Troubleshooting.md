## Troubleshooting Python 3.12 Virtual Environment Installation and Activation

When installing and managing virtual environments in Ubuntu (and other Linux operating systems), it is important to remember that the OS may require a specific version of python to perform operating system functions. For detection-rules we use Python version 3.12 which has a number of differences between older versions of Python, most notably no longer including `distutils` which can cause some unusual error messages. 

This section of the guide offers some solutions to some common problems that can occur if one inadvertently overwrites the system's Python 3 installation with Python version 3.12. 

### Issue: Python 3.12 system-wide installation replaced distutils links

If you installed Python 3.12 as a system-wide (or at least WSL wide) installation, it would have replaced the links to distutils from 3.10 with 3.12. However, since Python 3.12 no longer includes distutils as a core package, this will cause issues. 

Try installing python3.12-distutils using apt:

```bash
sudo apt install python3.12-distutils
```

If this command throws an error, you may need to fix apt first.

### Issue: apt's python3 management

If you're having issues with apt's python3 management, it might be due to a faulty python3-apt installation. Try reinstalling python3-apt with the following commands:

```bash
sudo apt remove --purge python3-apt
sudo apt autoclean
sudo apt install python3-apt
```

### Issue: Ubuntu needs to install python3.12-venv via apt

On Ubuntu, you need to install python3.12-venv via apt:

```bash
sudo apt install python3.12-venv
```


### Issue: Python 3.12 removed get-pip.py

Python 3.12 removed get-pip.py, but you can install pip using curl. If you don't have curl installed, you can install it using `sudo apt install curl`. Then, run the following commands:

```bash
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo python3.12 get-pip.py
```

### Issue: ensurepip not installed

If ensurepip is not installed, you can install it via pip:

```bash
python3.12 -m pip install ensurepip
```

