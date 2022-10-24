from setuptools import setup, find_packages

setup(
    name='albs-sign-file',
    version='0.1.0',
    packages=find_packages(include=['sign_file']),
    install_requires=[
        'python-gnupg == 0.5.0',
        'plumbum == 1.7.2',
        'fastapi[all] == 0.75.0',
        'fastapi-users[all] == 10.1.1',
        'aiofiles == 22.1.0',
        'pexpect == 4.8.0',
        'SQLalchemy == 1.4.42',
        'databases == 0.6.1',
        'bcrypt == 4.0.1',
    ]

)
