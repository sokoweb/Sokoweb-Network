# wait_for_postgres.py

import asyncio
import asyncpg
import sys
import os

async def check_postgres():
  retries = 20
  delay = 3  # seconds

  user = os.environ.get('POSTGRES_USER', 'postgres')
  password = os.environ.get('POSTGRES_PASSWORD', 'postgres')
  database = os.environ.get('POSTGRES_DB', 'sokoweb_db')
  host = os.environ.get('POSTGRES_HOST', 'postgres')
  port = 5432

  for i in range(retries):
      try:
          conn = await asyncpg.connect(
              user=user,
              password=password,
              database=database,
              host=host,
              port=port
          )
          await conn.close()
          print("Postgres is ready!")
          return
      except Exception as e:
          print(f"Attempt {i+1}/{retries}: Cannot connect to Postgres, retrying in {delay} seconds...")
          print(f"Exception: {e}")
          await asyncio.sleep(delay)
  print("Could not connect to Postgres after several retries, exiting.")
  sys.exit(1)

if __name__ == "__main__":
  asyncio.run(check_postgres())