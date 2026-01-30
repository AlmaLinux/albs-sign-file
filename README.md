# System Overview

<picture>
  <img alt="Test Coverage" src="https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andrewlukoshko/afe47ca11d7b469e40efab6eaede1cce/raw/coverage-badge.json">
</picture>
<br/><br/>

Service for signing various text files using PGP

## Signing Backends

The service supports two signing backends:

- **GPG** (default): Uses local GnuPG for signing operations
- **AWS KMS**: Uses AWS Key Management Service with PGP-compatible signature output

## Installation

### Prerequisites
1. Python 3.9+
2. For GPG backend: GnuPG binary and at least one private RSA key
3. For KMS backend: AWS credentials and KMS asymmetric signing keys

### Install service
1. Create virtual enviroment
    ```bash
    python3 -m venv .venv
    ```
2. Activate virtualenv
    ```bash
    source .venv/bin/activate
    ```
3. Install service with pip
    ```bash
    # For GPG backend only
    (.venv) pip3 install .

    # For AWS KMS backend (includes boto3, PGPy13, PyYAML)
    (.venv) pip3 install ".[kms]"
    ```

### Service configuration
Put in root dir `.env` file with service configuration parameters
EXAMPLE
```bash
# SF_GPG_BINARY - path to gpg binary
# default /usr/bin/gpg2
SF_GPG_BINARY="/usr/bin/gpg2"

# SF_KEYRING - path to keyring kbx file
# default ~/.gnupg/pubring.kbx
SF_KEYRING="~/.gnupg/pubring.kbx"

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
SF_PGP_KEYS_ID=["AAAA1111BBBB2222", "CCCC3333DDDD4444"]

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
# For SQLite (default):
SF_DB_URL="sqlite:///./sign-file.sqlite3"
# For PostgreSQL:
# SF_DB_URL="postgresql://signfile:signfile@localhost:5432/signfile"
# For PostgreSQL in docker-compose:
# SF_DB_URL="postgresql://signfile:signfile@postgres:5432/signfile"

# PostgreSQL Connection Pool Settings (optional, only for PostgreSQL)
# SF_DB_POOL_SIZE - number of connections to keep in the pool (default: 5)
# SF_DB_POOL_SIZE=5
# SF_DB_MAX_OVERFLOW - max connections beyond pool_size (default: 10)
# SF_DB_MAX_OVERFLOW=10
# SF_DB_POOL_RECYCLE - recycle connections after N seconds (default: 3600)
# SF_DB_POOL_RECYCLE=3600
# SF_DB_POOL_PRE_PING - verify connections before use (default: true)
# SF_DB_POOL_PRE_PING=true
# SF_DB_ECHO - enable SQL query logging for debugging (default: false)
# SF_DB_ECHO=false

# SF_HOST_GNUPG -  path of .gnupg directory on host
# this variable only used in docker-compose file
# default ""
SF_HOST_GNUPG="~/.gnupg"

# SF_ROOT_URL root URL for API calls
# default ""
# NOTE:
# You need to specify this parameter only if
# you`re planning to deploy service behind the proxy
# (see below)
SF_ROOT_URL=""

# The service that will use sign-file
# default "albs-sign-service"
TARGET_SERVICE="albs-sign-service"

# Sentry related vars
# SF_SENTRY_DSN to send server data to Sentry
SF_SENTRY_DSN = ""
# SF_SENTRY_TRACES_SAMPLE_RATE to specify percent of captured transactions for tracing (from 0.0 to 1.0)
SENTRY_TRACES_SAMPLE_RATE = 0.2
# SF_SENTRY_ENV for filtering purposes
SENTRY_ENV = "dev"

```

### YAML Configuration (Recommended)

For complex configurations, especially with AWS KMS, use a YAML config file.
Set the config file path via environment variable:

```bash
export SF_CONFIG_FILE=/etc/sign-file/config.yaml
```

**Example `config.yaml`:**

```yaml
# Signing backend: 'gpg' or 'kms'
signing_backend: kms

max_upload_bytes: 100000000
tmp_dir: /tmp
root_url: ""
service: albs-sign-service

# GPG backend configuration
gpg:
  binary: /usr/bin/gpg2
  keyring: ~/.gnupg/pubring.kbx
  locks_dir: /tmp/gpg_locks
  keys:
    - AAAA1111BBBB2222
    - CCCC3333DDDD4444

# AWS KMS backend configuration
kms:
  # AWS credentials (optional - uses env vars or IAM role if not set)
  # access_key_id: YOUR_ACCESS_KEY
  # secret_access_key: YOUR_SECRET_KEY
  region: us-east-1
  signing_algorithm: RSASSA_PKCS1_V1_5_SHA_256
  max_workers: 10
  keys:
    - kms_id: alias/almalinux-signing-key
      gpg_fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
    - kms_id: alias/secondary-signing-key
      gpg_fingerprint: FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000

# Database configuration
database:
  url: postgresql://signfile:password@localhost:5432/signfile
  pool_size: 5
  max_overflow: 10
  pool_recycle: 3600
  pool_pre_ping: true
  echo: false

# JWT configuration
jwt:
  secret_key: your-secret-key-here
  expire_minutes: 30
  algorithm: HS256

# Sentry configuration (optional)
sentry:
  dsn: ""
  traces_sample_rate: 0.2
  environment: dev
```

**Configuration Priority:**

Settings are loaded in this order (highest priority first):
1. Environment variables (`SF_*` prefix)
2. YAML config file
3. Default values

This allows keeping secrets (like `SF_JWT_SECRET_KEY`) in environment variables while having the rest in the YAML file.

### AWS KMS Backend Setup

The KMS backend produces PGP-compatible signatures that can be verified with standard `gpg --verify` commands.

#### Prerequisites

1. **AWS Credentials**: Configure via environment variables, AWS CLI, or IAM role
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. **KMS Key**: Create or import an asymmetric RSA signing key in AWS KMS
   - Key spec: `RSA_4096` (recommended) or `RSA_2048`
   - Key usage: `SIGN_VERIFY`

3. **IAM Permissions**: The service needs these KMS permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "kms:Sign",
           "kms:DescribeKey",
           "kms:GetPublicKey"
         ],
         "Resource": "arn:aws:kms:*:*:key/*"
       }
     ]
   }
   ```

#### Importing an Existing GPG Key into AWS KMS

If you have an existing GPG key, you can import it into AWS KMS using BYOK (Bring Your Own Key):

1. **Export your GPG private key:**
   ```bash
   gpg --export-secret-keys --armor YOUR_KEY_FINGERPRINT > private.asc
   ```

2. **Create KMS key with external origin:**
   ```bash
   aws kms create-key \
     --key-spec RSA_4096 \
     --key-usage SIGN_VERIFY \
     --origin EXTERNAL \
     --description "Imported GPG signing key"
   ```

3. **Get wrapping parameters:**
   ```bash
   aws kms get-parameters-for-import \
     --key-id <key-id> \
     --wrapping-algorithm RSA_AES_KEY_WRAP_SHA_256 \
     --wrapping-key-spec RSA_4096
   ```

4. **Prepare and import key material** using the provided `prepare_kms_key_material.py` script

5. **Configure the service** with the KMS key ID and corresponding GPG fingerprint in `config.yaml`

#### KMS Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `kms.access_key_id` | AWS access key ID | Uses env/IAM |
| `kms.secret_access_key` | AWS secret access key | Uses env/IAM |
| `kms.region` | AWS region | Uses `AWS_DEFAULT_REGION` |
| `kms.signing_algorithm` | KMS signing algorithm | `RSASSA_PKCS1_V1_5_SHA_256` |
| `kms.max_workers` | Max concurrent signing operations | `10` |
| `kms.keys` | List of KMS keys with GPG fingerprints | Required |

Each key in `kms.keys` requires:
- `kms_id`: KMS key ID or alias (e.g., `alias/my-key` or full ARN)
- `gpg_fingerprint`: The GPG fingerprint to embed in signatures (40 hex chars)

### Database initialization

#### Database Configuration
The service supports both SQLite and PostgreSQL databases:

**SQLite (Default)**
- Good for: Development, testing, simple deployments
- Configuration: `SF_DB_URL="sqlite:///./sign-file.sqlite3"`
- No additional setup required

**PostgreSQL (Recommended for Production)**
- Good for: Production deployments, concurrent access, better performance
- Configuration: `SF_DB_URL="postgresql://user:password@host:port/dbname"`
- Requires: Running PostgreSQL server
- Example: `SF_DB_URL="postgresql://signfile:signfile@localhost:5432/signfile"`
- Driver: Uses **psycopg2-binary** (reliable, battle-tested PostgreSQL adapter)

**PostgreSQL Optimizations:**

The service includes advanced connection pooling for PostgreSQL:

- **Connection Pooling**: Maintains a pool of reusable database connections
  - `SF_DB_POOL_SIZE=5`: Number of connections to keep open (default: 5)
  - `SF_DB_MAX_OVERFLOW=10`: Additional connections during traffic spikes (default: 10)
  
- **Connection Health**: 
  - `SF_DB_POOL_PRE_PING=true`: Validates connections before use (prevents stale connections)
  - `SF_DB_POOL_RECYCLE=3600`: Recycles connections after 1 hour (prevents timeout issues)
  
- **Monitoring**: 
  - `SF_DB_ECHO=false`: Enable SQL logging for debugging (set to `true` in development)
  - Connection pool statistics available via `get_pool_stats()` helper
  
- **Connection Settings**:
  - Connection timeout: 10 seconds
  - Pool timeout: 30 seconds
  - Application name: Identifies connections in PostgreSQL's `pg_stat_activity`

#### Creating Database and User

**Using Alembic Migrations (Recommended)**

Alembic provides version control for your database schema. This is the recommended approach:

1. Run migrations to create database tables:
   ```bash
   (.venv) python3 db_manage.py migrate_init
   Running database migrations...
   Migrations completed successfully
   command executed succesfully
   ```

2. Create a user:
   ```bash
   (.venv) python3 db_manage.py user_add
   email:kzhukov@cloudlinux.com
   password:
   password (repeat):
   user kzhukov@cloudlinux.com was created (uid: 1)
   command executed succesfully
   ```

**Additional Migration Commands:**
- `migrate_revision` - Create a new migration (with autogenerate)
- `migrate_upgrade` - Upgrade to the latest database version
- `migrate_downgrade` - Downgrade database by one version
- `migrate_history` - Show migration history

**Database Monitoring:**
- `pool_stats` - Show connection pool statistics (PostgreSQL only)

Example:
```bash
(.venv) python3 db_manage.py pool_stats
Database Connection Pool Statistics:
{
  "pool_size": 5,
  "checked_in": 4,
  "checked_out": 1,
  "overflow": 0,
  "total_connections": 5
}
command executed succesfully
```

**Legacy Method (Direct Table Creation)**

You can still use the direct table creation method:
   ```bash
    (.venv) python3 db_manage.py create
    command executed succesfully
   ```

However, this method doesn't provide version control and is deprecated in favor of Alembic migrations.


### Database Migrations with Alembic

The project uses Alembic for database schema version control. This allows you to:
- Track changes to your database schema over time
- Upgrade/downgrade between different schema versions
- Automatically generate migrations from model changes

#### Working with Migrations

**Creating a New Migration**

When you modify the database models in `sign/db/models.py`, create a new migration:

```bash
(.venv) python3 db_manage.py migrate_revision
Migration message: add new field to user table
Migration 'add new field to user table' created successfully
command executed succesfully
```

Alembic will automatically detect changes in your models and generate the migration file.

**Applying Migrations**

To apply all pending migrations:

```bash
(.venv) python3 db_manage.py migrate_upgrade
Upgrading database...
Database upgraded successfully
command executed succesfully
```

**Rolling Back Migrations**

To roll back the last migration:

```bash
(.venv) python3 db_manage.py migrate_downgrade
Downgrading database...
Database downgraded successfully
command executed succesfully
```

**Viewing Migration History**

To see the current migration status:

```bash
(.venv) python3 db_manage.py migrate_history
```

#### Migration Files

Migration files are located in the `alembic/versions/` directory. Each file contains:
- `upgrade()` function - applies the migration
- `downgrade()` function - reverts the migration

You can edit these files manually if needed, but be careful to maintain consistency.


### Service startup
Start service using `start.py` script

```bash
(.venv) % python3 start.py
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
SWAGGER API documentation available at `/docs` endpoint

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ping` | GET | Health check |
| `/sign` | POST | Sign a single file |
| `/sign-batch` | POST | Sign multiple files |
| `/token` | POST | Get JWT access token |

All signing endpoints work with both GPG and KMS backends. The `keyid` parameter accepts:
- For GPG: Key fingerprint (e.g., `AAAA1111BBBB2222`)
- For KMS: Key ID or alias (e.g., `alias/my-key`)

## Batch Signing Endpoint

The service includes a `/sign-batch` endpoint for signing multiple files in a single request. Files are processed asynchronously with I/O operations parallelized. For the GPG backend, exclusive locks and semaphores ensure safe GPG agent operation. For the KMS backend, concurrent signing is managed via a thread pool.

**Note:** The endpoint uses fail-fast behavior - if any file fails to sign, the entire batch operation fails immediately.

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
  'http://localhost:8000/sign?keyid=AAAA1111BBBB2222' \
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
  'http://localhost:8000/sign?keyid=AAAA1111BBBB2222&sign_type=clear-sign' \
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
gpg:                using RSA key AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
gpg: Good signature from "key1 (test key) <zklevsha@gmail.com>" [ultimate]
```


## Development mode
This section describes how to install service locally for development and tests

### Prerequisites
  1. For GPG backend: GnuPG
  2. For KMS backend: AWS credentials configured
  3. docker + docker-compose (optional)


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
  pub   rsa4096/AAAA1111BBBB2222 2022-10-26 [SC] [expires: 2024-10-25]
        AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555
  uid                 [ultimate] Your Name <your@email.com>
  ```
  For the example above keyid is __AAAA1111BBBB2222__

### Create configuration file (.env)
Create .env file with following  config 
```bash
# change this according your key password
SF_PASS_DB_DEV_PASS="<password>"
SF_PASS_DB_DEV_MODE=True
# change according your key id
SF_PGP_KEYS_ID=["AAAA1111BBBB2222"]
SF_JWT_SECRET_KEY="access-secret"
# change according your .gnupg location
SF_HOST_GNUPG="/home/<some_user>/.gnupg"

# Database configuration
# For PostgreSQL (recommended for production):
SF_DB_URL="postgresql://signfile:signfile@postgres:5432/signfile"
# For SQLite (simpler for local development):
# SF_DB_URL="sqlite:///./sign-file.sqlite3"
```

### Start service with docker-compose
```bash
sudo docker-compose up
[+] Running 3/3
 ⠿ Network albs-sign-file_default        Created                           0.7s
 ⠿ Container albs-sign-file-postgres-1   Created                           0.2s
 ⠿ Container albs-sign-file-sign_file-1  Created                           0.1s
Attaching to albs-sign-file-sign_file-1
albs-sign-file-sign_file-1  | initializing db for development
albs-sign-file-sign_file-1  | Running database migrations...
albs-sign-file-sign_file-1  | INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
albs-sign-file-sign_file-1  | INFO  [alembic.runtime.migration] Will assume transactional DDL.
albs-sign-file-sign_file-1  | INFO  [alembic.runtime.migration] Running upgrade  -> 001, Initial migration
albs-sign-file-sign_file-1  | Migrations completed
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

**Note:** By default, docker-compose now includes a PostgreSQL service. If you prefer to use SQLite, modify the `SF_DB_URL` in your `.env` file and remove the `depends_on` section from `docker-compose.yml`.

### Development with KMS Backend

For local development with the KMS backend:

1. **Create config file** `config.yaml`:
   ```yaml
   signing_backend: kms

   kms:
     region: us-east-1
     keys:
       - kms_id: alias/dev-signing-key
         gpg_fingerprint: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555

   database:
     url: sqlite:///./sign-file.sqlite3

   jwt:
     secret_key: dev-secret-key
   ```

2. **Set environment variables**:
   ```bash
   export SF_CONFIG_FILE=./config.yaml
   export AWS_ACCESS_KEY_ID=your-key
   export AWS_SECRET_ACCESS_KEY=your-secret
   export AWS_DEFAULT_REGION=us-east-1
   ```

3. **Start the service**:
   ```bash
   python3 start.py
   ```

4. **Test signing**:
   ```bash
   # Get token
   TOKEN=$(curl -s -X POST 'http://localhost:8000/token' \
     -H 'Content-Type: application/json' \
     -d '{"email":"test@test.ru","password":"test"}' | jq -r .token)

   # Sign a file
   curl -X POST 'http://localhost:8000/sign?keyid=alias/dev-signing-key' \
     -H "Authorization: Bearer $TOKEN" \
     -F 'file=@README.md' > README.md.asc

   # Verify signature
   gpg --verify README.md.asc README.md
   ```


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
