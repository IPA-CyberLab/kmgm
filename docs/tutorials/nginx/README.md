# nginx tutorial
In this tutorial, we setup a [nginx](https://www.nginx.com/) serving HTTPS using a certificate issued by [kmgm](https://github.com/IPA-CyberLab/kmgm).

## Prerequisites
- kmgm commandline tool installed. To install kmgm, please refer to the instructions [here](https://github.com/IPA-CyberLab/kmgm/blob/master/README.md#installation).
- kmgm git repository checkout on `/home/example/kmgm/` (Please replace the path with your actual checkout path in the instructions below)
  - To focus on kmgm usage, we use a pre-prepared nginx.conf and directory structure in this tutorial.
  - Checkout the repository via: `git clone https://github.com/IPA-CyberLab/kmgm`
- docker installation. Instructions [here](https://docs.docker.com/get-docker/).
  - We use docker in this tutorial to run nginx instance in a disposable manner. kmgm itself doesn't have any dependency to docker, so you can also run nginx directly on your machine.

## Setup a CA
Setup a new CA with the following command:

```bash
$ kmgm setup
```

kmgm launches `$EDITOR` to customize the CA settings. In this tutorial, the default settings are enough, so just close the editor.

## Generate a private key and issue a certificate
Let's change the working directory so we can save some typing later.
```bash
$ cd docs/tutorials/nginx/tls
```

Generate a new private key and issue a certificate using the CA setup in the previous section:

```bash
$ kmgm issue
```

kmgm will prompt you for the private key file path. Press the return key to proceed with the default, which is a `key.pem` right under the current working directory. kmgm will generate and write a new private key if it doesn't exist.
```
✔ Private key file: /home/example/kmgm/docs/tutorials/nginx/tls/key.pem
```

Next, kmgm will prompt you for the certificate file path. Again, press the return key to proceed with the default. kmgm will issue a fresh new certificate on the specified path, or renew an existing certificate if the file already exists:
```
✔ Certificate pem file: /home/example/kmgm/docs/tutorials/nginx/tls/key.pem
```

Finally, kmgm launches `$EDITOR` to customize the certificate details. In this tutorial, the default settings are enough, so just close the editor, and kmgm will handle the rest:

```
INFO	Generating key...	{"usage": "", "type": "rsa"}
INFO	Generating key... Done.	{"usage": "", "type": "rsa", "took": 0.838800879}
INFO	Allocated sn: 6362397607487909327
INFO	Generating certificate...
INFO	Generating certificate... Done.	{"took": 0.006699632}
```

After the kmgm command finishes, you should have the pem files populated:
```
$ ls -l
total 8
-rw-r--r-- 1 example example 1939 May 25 23:30 cert.pem
-r-------- 1 example example 3243 May 25 23:30 key.pem
```

## Run nginx
Now that you have a private key and a certificate, let's configure a `nginx.conf` to use them:
```nginx
events {}

http {
  server {
    listen 443 ssl http2;
  
    ssl_certificate /etc/tls/cert.pem; # replace with the certificate file path
    ssl_certificate_key /etc/tls/key.pem; # replace with the key file path
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
  
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    root /pub; # replace with the directory which you wish to publish
  }
}
```

If you have docker installed, we can run nginx like below:
```bash
$ cd .. # cd to [checkout]/docs/tutorials/nginx
$ docker run --rm -v `pwd`/tls:/etc/tls:ro -v `pwd`/conf:/etc/nginx:ro -v `pwd`/pub:/pub:ro -p 8443:443 nginx
```

You should be able to test the nginx instance by navigating your web browser to https://[your hostname]:8443/.

## CA root
When you navigate to the nginx instance, your browser would warn you that the CA is invalid.
![Chrome warning][chrome-warning]

To avoid the warning, we need to import the CA we just setup as a trusted root. To show the CA certificate info, use:
```bash
$ kmgm show ca
```

To output only pem part, do
```bash
$ kmgm show -o pem ca
```
or, to save the result to a pem file,
```bash
$ kmgm show -o pem -f ca.pem
```

To import the CA certificate to chrome, type `chrome://settings/certificates` into the omnibox (URL bar), and click on `Import`.

<!-- Markdown link & img dfn's -->
[chrome-warning]: https://raw.githubusercontent.com/IPA-CyberLab/kmgm/master/docs/tutorials/nginx/chrome-warning.png
