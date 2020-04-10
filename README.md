# pySockSSL

[![Python 3](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/)

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

## Usage

```bash
$ sockssl --help
Usage: sockssl [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  genca  Generate root CA
  run    Run a standalone SOCKS server
```

- Generate root CA

```
sockssl genca rootCA.crt rootCA.key -org mycompany -cn myCA
```

- Run server

```bash
# Socks4/Socks5 no TLS mitm
sockssl run v4
sockssl run v5

# Mitm Socks4
sockssl run v4 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999

# Mitm Socks4 + auth with multiple usernames
sockssl run v4 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999 -u user1 -u user2

# Mitm Socks5
sockssl run v5 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999

# Mitm Socks5 + auth with multiple users + passwords
sockssl run v5 -c rootCA.crt -k rootCA.key -h 0.0.0.0 -p 9999 -u user1 pass1 -u user2 pass2
```

- Proxy your clients

- Don't forget to trust `rootCA.crt` if you want to capture TLS data

## TODO

- Interactive interface
- CLI addon to save dummy cert from rootCA
- Blacklist / whitelist / passthru TLS Domain

## License

GNU GPLv3