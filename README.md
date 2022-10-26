# ALBS-SIGN-FILE
Service for signing various text files using PGP 
This service created for task 
https://cloudlinux.atlassian.net/browse/ALBS-681

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
4. Create database and user with `db_manage.py` script
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


### Service configuration
Put in root dir `.env` file with service configuration parameters
EXAMPLE
```bash
# SF_GPG_BINARY - path to gpg binary
# default /ust/bin/gpg2
SF_GPG_BINARY="/ust/bin/gpg2"

# SF_KEYRING - path to keyring kbx file
# default /home/alt/.gnupg/pubring.kbx
SF_KEYRING="/Users/alt/.gnupg/pubring.kbx"

# SF_MAX_UPLOAD_BYTES - max file size (in bytes )to sign
# default 100000000
SF_MAX_UPLOAD_BYTES=100000000

# SF_PASS_DB_DEV_PASS
# password for PGP private key (DO NOT USE IT IN PROD)
# default ""
SF_PASS_DB_DEV_PASS= "secret2"

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

## Sign file
### Request
```bash
'http://localhost:8000/sign?keyid=EF0F6DF0AFE52FD5' \
  -H 'accept: text/plain' \
  -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6Imt6aHVrb3ZAY2xvdWRsaW51eC5jb20iLCJleHAiOjE2NjY3ODI0OTJ9.SdqG6ex_VWtHXzXQXuzIUGnWaKY7HFrrMrwmLVYPwH4' \
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

### Check PGP signature (optional)
Save response as `<filename>.acs` and run `gpg2 --verify <filename>.acs <filename>`
```bash
gpg2 --verify README.md.acs README.md
gpg: Signature made среда, 26 октября 2022 г. 10:43:15 CEST
gpg:                using RSA key B1427E1CEA16226DFEB13A62EF0F6DF0AFE52FD5
gpg: Good signature from "key1 (test key) <zklevsha@gmail.com>" [ultimate]
```


