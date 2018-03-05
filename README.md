# IronScanner

![Logo](src/ironscanner/logo.png)

Collect as much information as possible on image scanners and send it to [OpenPaper.work](https://openpaper.work/).


## Linux

```sh
cd /tmp
wget https://download.openpaper.work/linux/amd64/ironscanner/latest/ironscanner
chmod +x /tmp/ironscanner
./ironscanner
```


## Windows

[Download](https://download.openpaper.work/windows/amd64/ironscanner.exe), click "yes" on the ten of thousands security warnings, and run.


## Development

```sh
virtualenv -p python3 --system-site-packages venv
source venv/bin/activate
python3 ./setup.py install
ironscanner
```
