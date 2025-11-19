#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Kirill Zhukov <kzhukov@cloudlinux.com>
# created: 2022-10-21
"""
Database management script
"""

import getpass
import json
import sys

from alembic import command
from alembic.config import Config
from sign.db.helpers import (
    create_user,
    db_create,
    db_drop,
    db_is_connected,
    delete_user,
    get_pool_stats,
    update_password,
    user_exists,
)

DEV_USER_EMAIL = 'test@test.ru'
DEV_USER_PASSWORD = 'test'


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


def dev_init():
    print('initializing db for development')
    # Use migrations instead of direct table creation
    print('Running database migrations...')
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print('Migrations completed')

    if not user_exists(DEV_USER_EMAIL):
        create_user('test@test.ru', 'test')
        print('development user was created: login:test@test.ru password:test')


def migrate_init():
    """Initialize alembic and run migrations to latest version"""
    print('Running database migrations...')
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print('Migrations completed successfully')


def migrate_revision():
    """Create a new migration revision"""
    message = input("Migration message: ")
    if len(message) == 0:
        print_and_exit("ERROR: migration message is required", 1)
    alembic_cfg = Config("alembic.ini")
    command.revision(alembic_cfg, message=message, autogenerate=True)
    print(f"Migration '{message}' created successfully")


def migrate_upgrade():
    """Upgrade database to latest version"""
    print('Upgrading database...')
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print('Database upgraded successfully')


def migrate_downgrade():
    """Downgrade database by one version"""
    print('Downgrading database...')
    alembic_cfg = Config("alembic.ini")
    command.downgrade(alembic_cfg, "-1")
    print('Database downgraded successfully')


def migrate_history():
    """Show migration history"""
    alembic_cfg = Config("alembic.ini")
    command.history(alembic_cfg)


def pool_stats():
    """Show database connection pool statistics"""
    try:
        stats = get_pool_stats()
        print("Database Connection Pool Statistics:")
        print(json.dumps(stats, indent=2))
    except Exception as e:
        print(f"Error getting pool stats: {e}")
        print("Note: Pool statistics are only available for PostgreSQL")


def db_health():
    """Check database connection health"""
    print("Checking database connection...")
    if db_is_connected():
        print("✓ Database connection successful")
        return
    print("✗ Database connection failed!")
    print("Please check your database configuration and connectivity")
    sys.exit(1)


cmds = {
    'create': {
        'func': db_create,
        'descr': 'creates database tables (deprecated, use migrate_init)',
    },
    'drop': {'func': db_drop, 'descr': 'drops database tables'},
    'user_add': {'func': user_add, 'descr': 'creates new user'},
    'user_reset_pass': {
        'func': user_reset_pass,
        'descr': 'update user`s password',
    },
    'user_delete': {'func': user_delete, 'descr': 'delete user'},
    'dev_init': {
        'func': dev_init,
        'descr': 'creating development database with test user',
    },
    'migrate_init': {
        'func': migrate_init,
        'descr': 'run all migrations to setup database',
    },
    'migrate_revision': {
        'func': migrate_revision,
        'descr': 'create new migration revision (autogenerate)',
    },
    'migrate_upgrade': {
        'func': migrate_upgrade,
        'descr': 'upgrade database to latest version',
    },
    'migrate_downgrade': {
        'func': migrate_downgrade,
        'descr': 'downgrade database by one version',
    },
    'migrate_history': {
        'func': migrate_history,
        'descr': 'show migration history',
    },
    'pool_stats': {
        'func': pool_stats,
        'descr': 'show database connection pool statistics (PostgreSQL)',
    },
    'db_health': {
        'func': db_health,
        'descr': 'check database connection health',
    },
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

    print("command executed successfully")


if __name__ == "__main__":
    run()
