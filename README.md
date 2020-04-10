# pySockSSL

[![Python 3](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/) [![Documentation Status](https://readthedocs.org/projects/pysockssl/badge/?version=latest)](https://pysockssl.readthedocs.io/en/latest/?badge=latest)

Similar to 
- [Burpsuite](https://portswigger.net/burp) 
- [mitmproxy](https://mitmproxy.org/)
- [Charles Proxy](https://www.charlesproxy.com/)
- [Fiddler](https://www.telerik.com/fiddler)
- and many more ...

But more simple and focus on TCP/TLS stream capture ONLY - NO data analyzing 🤐

## Support

- TCP only
- SOCKSv4 + user auth
- SOCKSv5 + user/pwd auth
- [Dummy] cert generator
- SSL/TLS man-in-the-middle 😎
- API to intercept captured data

## Install

```bash
pip3 install pysockssl
```

or

```bash
git clone https://github.com/trichimtrich/pysockssl
cd pysockssl
python3 setup.py install
```

## Usage & API

Check out the doc at [https://pysockssl.readthedocs.io](https://pysockssl.readthedocs.io)

## TODO

- Interactive interface
- CLI addon to save dummy cert from rootCA
- Blacklist / whitelist / passthru TLS Domain

## License

GNU GPLv3