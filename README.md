# System Overview

<picture>
  <img alt="Test Coverage" src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andrewlukoshko/afe47ca11d7b469e40efab6eaede1cce/raw/coverage-badge.json">
</picture>
<br/><br/>

Service for signing various text files using PGP  

## Installation

### Prerequirements
1. GnuPGP binary
2. At least one private RSA key in PGP database
3. Python3.9 with virtualenv

### Install service
1. Create virtual enviroment
    ```bash
    virtualenv -p python3.9 env
    ```
2. Activate virtualenv
    ```bash
    source env/bin/activate
    ```
3. Install service with pip
    ```bash
    (env) python -m pip install .
    ```

### Service configuration
Put in root dir `.env` file with service configuration parameters
EXAMPLE
```bash
# SF_GPG_BINARY - path to gpg binary
# default /usr/bin/gpg2
SF_GPG_BINARY="/usr/bin/gpg2"

# SF_KEYRING - path to keyring kbx file
# default /home/alt/.gnupg/pubring.kbx
SF_KEYRING="/home/alt/.gnupg/pubring.kbx"

# SF_MAX_UPLOAD_BYTES - max file size (in bytes )to sign
# default 100000000
SF_MAX_UPLOAD_BYTES=100000000

# SF_PASS_DB_DEV_PASS
# password for PGP private key (DO NOT USE IT IN PROD)
# default ""
SF_PASS_DB_DEV_PASS="secret2"

# SF_PASS_DB_DEV_MODE - if True PGP key password
# will be retrived from SF_PASS_DB_DEV_PASS 
# instead of asking for it interactevly
# default False
SF_PASS_DB_DEV_MODE=False

# SF_TMP_FILE_DIR - directory in wich temporaty files will be created
# default /tmp
SF_TMP_FILE_DIR ="/tmp"

# SF_PGP_KEYS_ID - list of PGP key ids that will be used for file signing
# default N/A
SF_PGP_KEYS_ID=["EF0F6DF0AFE52FD5", "0673DB399D3E2894"]

# SF_JWT_EXPIRE_MINUTES - JWT token lifetime (in minutes)
# default 30
SF_JWT_EXPIRE_MINUTES=30

# SF_JWT_ALGORITHM - hashing algoritm used for JWT token creation
# defaul HS256
SF_JWT_ALGORITHM="HS256"

# SF_JWT_SECRET_KEY - secret key for JWT token signing (must be secret)
# default N/A
SF_JWT_SECRET_KEY="access-secret"

# SF_DB_URL - database url
# default sqlite:///./sign-file.sqlite3
SF_DB_URL="sqlite:///./sign-file.sqlite3"

# SF_HOST_GNUPG -  path of .gnupg directory on host
# this variable only used in docker-compose file
# default ""
SF_HOST_GNUPG="/home/kzhukov/.gnupg"

# SF_ROOT_URL root URL for API calls
# default ""
# NOTE:
# You need to specify this parameter only if
# you`re planning to deploy service behind the proxy
# (see below)
SF_ROOT_URL=""

```

### Database initialization
Create database and user with `db_manage.py` script
   ```bash
    (env) python db_manage.py create
    command executed succesfully

    (env) python db_manage.py user_add
    email:kzhukov@cloudlinux.com
    password:
    password (repeat):
    user kzhukov@cloudlinux.com was created (uid: 1)
    command executed succesfully
   ```


### Service startup
Start service using `startup.py` script

```bash
(env) % python start.py
INFO:     Will watch for changes in these directories: ['/Users/kzhukov/projects/cloudlinux/albs-sign-file']
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
DEBUG:    WatchGodReload detected a new excluded dir '.pytest_cache' in '/Users/kzhukov/projects/cloudlinux/albs-sign-file'; Adding to exclude list.
DEBUG:    WatchGodReload detected a new excluded dir '.git' in '/Users/kzhukov/projects/cloudlinux/albs-sign-file'; Adding to exclude list.
DEBUG:    WatchGodReload detected a new excluded dir '.vscode' in '/Users/kzhukov/projects/cloudlinux/albs-sign-file'; Adding to exclude list.
INFO:     Started reloader process [27902] using watchgod
INFO:     Started server process [27904]
[2022-10-26 10:34:04,600] INFO - Started server process [27904]
INFO:     Waiting for application startup.
[2022-10-26 10:34:04,600] INFO - Waiting for application startup.
INFO:     Application startup complete.
[2022-10-26 10:34:04,601] INFO - Application startup complete.
```

# API Reference
SWAGGER API documentaion available at /docs enpoint

# Basic usage

## Get access token 
### Request
```bash
curl -X 'POST' \
  'http://localhost:8000/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "kzhukov@cloudlinux.com",
  "password": "test"
}'
```

### Response
```
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Imt6aHVrb3ZAY2xvdWRsaW51eC5jb20iLCJleHAiOjE2NjY3ODI0OTJ9.SdqG6ex_VWtHXzXQXuzIUGnWaKY7HFrrMrwmLVYPwH4","user_id":1,"exp":1666775292}
```

## Sign file with detached signature
### Request
```bash
curl -X 'POST' \
  'http://localhost:8000/sign?keyid=EF0F6DF0AFE52FD5' \
  -H 'accept: text/plain' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Imt6aHVrb3ZAY2xvdWRsaW51eC5jb20iLCJleHAiOjE2NjY3ODI0OTJ9.SdqG6ex_VWtHXzXQXuzIUGnWaKY7HFrrMrwmLVYPwH4' \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@README.md;type=text/plain'
```
### Response
```bash
-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEEsUJ+HOoWIm3+sTpi7w9t8K/lL9UFAmNY8tgACgkQ7w9t8K/l
L9W2BRAAio4mbaDgPu9U4pG1cpQevuLacF6Mt+a4HwWisF5IA0b/zULkaqxJbLR0
UbphL+9M9joKn1JMiPqKLDqEYC9pPHH5CHOgftnDn/n52E+EZtAhmOb0WWkT29wZ
ulDeFsu+KbmbBPECCyVwSH83JXOAjYUId6W7rdt0Ax5f/uD6iiFLrKr1sx4nquN/
8Ze2ENKSKAVHZrWYklMnoCGnePFnwsNc3Wg0XmPu+YEWe4bA7Gy/z490AgrI3Sgq
G/QBhrscr+wKxYS2MZKIoLLdW2kL8S699pVU+9bqZMLg1bsMNTggFuTW/i3o5/y+
Abfl3nTXnQ7Lzkscs4k7PpRvsnuVH1P7PYh7q2wZhLQoTdF5JWkCVsqn1DbcoeYJ
F12UC7zU7HL6f7w/GI7irnhy5uLCcjmvvw/IXa3E+GBOF7jIOJmYFQRyrzqTtrrN
TYCmN3QiFJqnINGs/gpFVB8WK5jWb8t2gc9tiRVVQ/gGnIzJtBVMd++NafZNxbpG
8EAvSXFmhttWZE1BnA6/d32C9BvD2WVGvtjFLabhBniiTrTI/UItYxdkmty+cI0I
kqqSe4lK32Q2eVxMKgDojhE7l9S4oBWoaKPV0twacIXcJYVlfJ5eEFWX3neJf3Cg
JLI3A3hL2JnhxPgIw2uoKbgZ6xhU59K+LzX+tzxmvzUeBFYg0+Y=
=NfH2
-----END PGP SIGNATURE-----
```

### Python example
```python
import requests
from urllib.parse import urljoin

EMAIL = 'test@test.ru'
PASSWORD = 'test'
BASE_URL = 'http://localhost:8000'
PATH_TO_FILE = '/tmp/test.txt'
KEYID = '' # SET IT YOURSELF


def get_token(email: str = EMAIL, password: str = PASSWORD) -> str:
    endpoint = '/token'
    full_url = urljoin(BASE_URL, endpoint)
    body = {'email': email, 'password': password}
    response = requests.post(url=full_url, json=body)
    response.raise_for_status()
    return response.json()['token']


def sign_file(path_to_file: str = PATH_TO_FILE, 
              keyid: str  = KEYID):
    headers = {'Authorization': f"Bearer {get_token()}"}
    endpoint = '/sign'
    full_url = urljoin(BASE_URL, endpoint)
    params = {'keyid': keyid}
    files = {'file': open(path_to_file,'rb')}

    response = requests.post(url=full_url, headers=headers,
                             files=files, params=params)
    response.raise_for_status()

    return response.text


if __name__ == '__main__':
    print(sign_file())
```

## Sign file with clear signature
### Request
```bash
curl -X 'POST' \
  'http://localhost:8000/sign?keyid=EF0F6DF0AFE52FD5&sign_type=clear-sign' \
  -H 'accept: text/plain' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Imt6aHVrb3ZAY2xvdWRsaW51eC5jb20iLCJleHAiOjE2NjY3ODI0OTJ9.SdqG6ex_VWtHXzXQXuzIUGnWaKY7HFrrMrwmLVYPwH4' \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@test;type=text/plain'
```
### Response
```bash
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

line1
line2
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEENuDOMZ0vGM8wTisq/bHGsUxl8KwFAmQ+/KwACgkQ/bHGsUxl
8Kx09hAAj/pIvQcRlTgvq1b53wiHz02wkqVW/BLGzeLY3/DU2ilSHPUWKLoaciZ8
QDgWcowtAKIn6O6APWK3MJvnvUw0KitLYiuP+0OibKAWEbvaBtzbOOXDB8AfRMZS
hImsb9fFfONpnq/xO+149kwtNZOFzShuKyHHKfhm+117qjKVScvGXdD//GT31UN0
qnwBnkHFZq+gojDgzSTQai3/DkNbJdvv9s1bhwjVuRfk8wPpAWNbvuSt/74sUjgf
+1711KxNHt/FZReRSpS6ZFdziMrnCsHdFTyDiN33Np7vUF+0Y+d6rcT9K9DwRvep
9jGhfDNzuPnevWFTWk6lj7BO4r2C81nObHKAkMDNGeSFpXFOA6k8DGjZZEloY3WI
NRwL/nXbexso0afpAYKrC51W7VWb4SoIGoHPP19dtQ+yzZlblbxH+7nOwIXWBl5B
D5IBHATpSCoz3IlidhrM6KfgDrIe+vL/1QhNGMTY3DL+uxaa0f4L9mCne98e6zxV
Ta3NteGiLbP76aLxE8H2zVj5D8Xt00RGoZ9OpZ2BmBY0maBPBPG2an7llHwxU0SY
zE5NAiSJ18XMkeLiwkO7tG3BOoqxQsegJOrT5YZjSfkDC/+QXLegpdvN0RNXlXAn
fiqWYJ3GstPN3kEySzdxmfmkzFj2J0GilFAyYogq+SasFh2lLZQ=
=9qdc
-----END PGP SIGNATURE-----
```

### Check PGP signature (optional)
Save response as `<filename>.acs` and run `gpg2 --verify <filename>.acs <filename>`
```bash
gpg2 --verify README.md.acs README.md
gpg: Signature made среда, 26 октября 2022 г. 10:43:15 CEST
gpg:                using RSA key B1427E1CEA16226DFEB13A62EF0F6DF0AFE52FD5
gpg: Good signature from "key1 (test key) <zklevsha@gmail.com>" [ultimate]
```


## Development mode
This section describes how to install service locally for development and tests

### Prerequirements
  1. gnupgp
  2. docker + docker-compose


### Key generation
### Create rsa key
  ```bash
    gpg --default-new-key-algo rsa4096 --gen-key
  ```
### Check rsa keyid (hex value after "pub  rsa4096/")
  ```bash
  gpg --list-key --keyid-format long
  /home/kzhukov/.gnupg/pubring.kbx
  --------------------------------
  pub   rsa4096/03A5E40D1ABD030B 2022-10-26 [SC] [expires: 2024-10-25]
        7AE918401B9F0EF36B7A5E7303A5E40D1ABD030B
  uid                 [ultimate] Kirill Zhukov <kzhukov@test.ru>
  ```
  For the example above keyid is __03A5E40D1ABD030B__

### Create configuration file (.env)
Create .env file with following  config 
```bash
# change this according your key password
SF_PASS_DB_DEV_PASS="<password>"
SF_PASS_DB_DEV_MODE=True
# change according your key id
SF_PGP_KEYS_ID=["03A5E40D1ABD030B"]
SF_JWT_SECRET_KEY="access-secret"
# change according your .gnupg location
SF_HOST_GNUPG="/home/<some_user>/.gnupg"
```

### Start service with docker-compose
```bash
sudo docker-compose up
[+] Running 2/2
 ⠿ Network albs-sign-file_default        Created                           0.7s
 ⠿ Container albs-sign-file-sign_file-1  Created                           0.1s
Attaching to albs-sign-file-sign_file-1
albs-sign-file-sign_file-1  | initializing db for development
albs-sign-file-sign_file-1  | database created
albs-sign-file-sign_file-1  | development user was created: login:test@test.ru password:test
albs-sign-file-sign_file-1  | command executed succesfully
albs-sign-file-sign_file-1  | INFO:     Will watch for changes in these directories: ['/app']
albs-sign-file-sign_file-1  | INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
albs-sign-file-sign_file-1  | INFO:     Started reloader process [1] using watchgod
albs-sign-file-sign_file-1  | INFO:     Started server process [8]
albs-sign-file-sign_file-1  | [2022-10-26 23:21:29,762] INFO - Started server process [8]
albs-sign-file-sign_file-1  | INFO:     Waiting for application startup.
albs-sign-file-sign_file-1  | [2022-10-26 23:21:29,764] INFO - Waiting for application startup.
albs-sign-file-sign_file-1  | INFO:     Application startup complete.
albs-sign-file-sign_file-1  | [2022-10-26 23:21:29,764] INFO - Application startup complete.
```

After startup service will be available at http://hostip:8000 (make sure that 8000 port is open). Also there is a test user created: `login:test@test.ru password:test`


# Deploy service behind the Nginx

1. Set `SF_ROOT_URL` in .env file to the prefix you like to serve service from
    ```
    SF_ROOT_URL="/sign-file"
    ```
  
2. Add location to Nginx config
    ```
    upstream signfile {
      server <ip:port>;
    }

    server {
      [... other configs ...]

      location /sign-file/ {
          proxy_set_header Host $http_host;
        proxy_pass http://signfile/;
      }
    }
    ```