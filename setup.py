from setuptools import find_packages, setup

setup(
    name='sign',
    version='0.1.0',
    packages=find_packages(include=['sign']),
    install_requires=[
        'python-gnupg >= 0.5.6',
        'plumbum >= 1.10.0',
        'fastapi[all] >= 0.128.0',
        'aiofiles >= 22.1.0',
        'pexpect >= 4.8.0',
        'SQLAlchemy >= 1.4.42, < 3.0',
        'bcrypt >= 4.0.1',
        'pyjwt >= 2.4.0',
        'sentry-sdk >= 2.22.0',
        'psycopg2-binary >= 2.9.3',
        'alembic >= 1.13.1',
        'PyYAML >= 6.0',
    ],
    extras_require={
        'kms': [
            'boto3 >= 1.26.0',
            'PGPy13 >= 0.6.1rc1',
        ],
    },
)
