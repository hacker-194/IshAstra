from logging.config import fileConfig
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sqlalchemy import engine_from_config, MetaData
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import Strix models for autogenerate support
# The models are defined as raw SQL in store.py MIGRATIONS list
# We create a MetaData and reflect the current database state
target_metadata = MetaData()

# Read database URL from environment (same as Settings.from_env())
def get_database_url() -> str:
    """Get database URL from environment variables."""
    # STRIX_DATABASE_URL takes precedence (PostgreSQL)
    database_url = os.environ.get("STRIX_DATABASE_URL", "").strip()
    if database_url:
        return database_url
    # Fallback to SQLite
    db_path = os.environ.get("STRIX_DB", "strix.db")
    if db_path.startswith("postgresql://") or db_path.startswith("postgres://"):
        return db_path
    # SQLite file path
    return f"sqlite:///{db_path}"

# Override sqlalchemy.url from environment
config.set_main_option("sqlalchemy.url", get_database_url())

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
