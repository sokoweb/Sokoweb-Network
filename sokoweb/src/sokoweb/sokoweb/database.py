
# database.py
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

# Default values for database connection
POSTGRES_USER = os.getenv('POSTGRES_USER', 'postgres')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'postgres')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'sokoweb_db')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'postgres')  # Use 'localhost' if not using Docker
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')

# Construct the DATABASE_URL
DATABASE_URL = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

if not DATABASE_URL:
    raise ValueError("Could not construct database URL")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to False in production
)

async_session = sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)

Base = declarative_base()