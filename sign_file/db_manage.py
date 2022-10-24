#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Kirill Zhukov <kzhukov@cloudlinux.com>
# created: 2022-10-21
"""
Database management script
"""

import sys
import getpass
from db.helpers import (db_create, db_drop, create_user,
                        update_password, delete_user)


def print_and_exit(msg: str, exit_code: int = 0):
    print(msg)
    sys.exit(exit_code)


def user_add():
    email = input("email:")
    if len(email) == 0:
        print_and_exit("ERROR username is not set", 1)
    p1 = getpass.getpass("password:")
    if len(p1) == 0:
        print_and_exit("ERROR: password is not set", 1)
    p2 = getpass.getpass("password (repeat):")
    if p1 != p2:
        print_and_exit("ERROR: passwords don`t match", 1)
    uid = create_user(email, p1)
    print(f"user {email} was created (uid: {uid})")


def user_reset_pass():
    email = input("email:")
    if len(email) == 0:
        print_and_exit("ERROR username is not set", 1)
    p1 = getpass.getpass("password:")
    if len(p1) == 0:
        print_and_exit("ERROR: password is not set", 1)
    p2 = getpass.getpass("password (repeat):")
    if p1 != p2:
        print("ERROR: passwords don`t match")
        sys.exit(0)
    update_password(email, p1)


def user_delete():
    email = input("email: ")
    if len(email) == 0:
        print_and_exit("ERROR username is not set", 1)
    delete_user(email)


cmds = {
    'create': {'func': db_create, 'descr': 'creates database tables'},
    'drop': {'func': db_drop, 'descr': 'drops database tables'},
    'user_add': {'func': user_add, 'descr': 'creates new user'},
    'user_reset_pass': {'func': user_reset_pass, 'descr': 'update user`s password'},
    'user_delete': {'func': user_delete, 'descr': 'delete user'},
}


def usage():
    print(f'USAGE: {sys.argv[0]} <command>')
    print('Supported commands:')
    for k, v in cmds.items():
        print(f"\t{k}\t{v['descr']}")


def run():
    try:
        cmd = sys.argv[1]
    except IndexError:
        print('ERROR: command expected')
        usage()
        sys.exit(1)
    try:
        cmds[cmd]['func']()
    except KeyError:
        print(f"ERROR: unsupported command {cmd}")
        usage()
        sys.exit(1)

    print("command executed succesfully")


if __name__ == "__main__":
    run()
