#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Kirill Zhukov <kzhukov@cloudlinux.com>
# created: 2022-10-21
"""
Database management script
"""

import sys
from db.helpers import db_create, db_drop

cmds = {
    'create': {'func': db_create, 'descr': 'creates database tables'},
    'drop': {'func': db_drop, 'descr': 'drops database tables'}
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
