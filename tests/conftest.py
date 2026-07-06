import os

# sign.config.create_settings() now refuses to load with no configuration
# source (no config file and no SF_DB_URL), to avoid silently falling back to
# a local SQLite database. The unit tests import sign.config transitively but
# do not touch the database, so provide a throwaway in-memory URL before any
# test module imports sign.config.
os.environ.setdefault('SF_DB_URL', 'sqlite:///:memory:')
