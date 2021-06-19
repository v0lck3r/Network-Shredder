# Network-Shredder
Network-Shredder est un IDS écrit en Python.
![](./source/static/logo.png)


## Installation

```bash
git clone https://github.com/v0lck3r/Network-Shredder.git
cd Network-Shredder
pip3 install -r requirements.txt
```

## Example usage

### Help menu 

```bash
python3 Network-Shredder.py -h
````
![](./source/static/shredder.PNG)

## Live mode 

```bash 
python3 Network-Shredder.py rules.txt --interface tun0
```

## Start web application 

```bash 
python3 Network-Shredder.py rules.txt --interface tun0 --web
```

## Console quite mode 

```bash 
python3 Network-Shredder.py rules.txt --interface tun0 --web --quite
```
## Pcap based detection 

```bash 
python3 Network-Shredder.py rules.txt --pcap pcap_file.pcap
```
