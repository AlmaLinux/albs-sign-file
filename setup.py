from setuptools import find_packages, setup

setup(
    name='sign',
    version='0.1.0',
    packages=find_packages(include=['sign']),
    install_requires=[
        'python-gnupg == 0.5.0',
        'plumbum == 1.10.0',
        'fastapi[all] == 0.75.0',
        'fastapi-users[all] == 10.1.1',
        'aiofiles == 22.1.0',
        'pexpect == 4.8.0',
        'SQLalchemy == 1.4.42',
        'databases == 0.6.1',
        'bcrypt == 4.0.1',
        'pyjwt == 2.4.0',
        'sentry-sdk == 2.22.0',
        'psycopg2-binary >= 2.9.3, < 3.0',
        'alembic == 1.13.1',
    ],
)
