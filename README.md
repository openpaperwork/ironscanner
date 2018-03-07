# IronScanner

![Logo](src/ironscanner/logo.png)

Collect as much information as possible on a image scanner, run test scan, and send a detailed report to [OpenPaper.work](https://openpaper.work/scanner_db/).


## Linux

```sh
cd /tmp
wget https://download.openpaper.work/linux/amd64/ironscanner/latest/ironscanner
chmod +x /tmp/ironscanner
./ironscanner
```


## Windows

[Download](https://download.openpaper.work/windows/amd64/ironscanner.exe), click "yes" on the ten of thousands of security warnings, and run.


## From sources

Requires python3 + python3-virtualenv + python3-setuptools.

```sh
cd /tmp
git clone https://github.com/openpaperwork/ironscanner.git
cd ironscanner
virtualenv -p python3 --system-site-packages venv
source venv/bin/activate
python3 ./setup.py install
ironscanner
```
