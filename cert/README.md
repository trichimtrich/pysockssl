## Ref

https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs

## generate rootCA

```
openssl req -newkey rsa:4096 -nodes -keyout rootCA.key -x509 -days 365 -out rootCA.crt -subj "/C=US/ST=New York/L=Brooklyn/O=concavang/CN=conchimnon"
```

## generate signed cert for example.com

- Change `DNS = example.com` in `san.conf`

```
openssl req -newkey rsa:4096 -nodes -keyout example.com.key -out example.com.csr -config san.conf -subj "/C=US/ST=New York/L=Brooklyn/O=cong ti X/CN=example.com"

openssl x509 -req -days 3650 -in example.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out example.com.crt -extensions v3_req -extfile san.conf
```