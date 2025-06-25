from ast import stmt
import os
from sqlalchemy import create_engine, Column, String, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert
from key_manager import KeyManager

class PostgresKeyManager(KeyManager):
    def __init__(self, db_url='postgresql://postgres:password@postgres:5432/keydb'):
        self.engine = create_engine(db_url, pool_size=10, max_overflow=20)
        self.metadata = MetaData()
        self.keys_table = Table('keys', self.metadata,
                                Column('key_name', String, primary_key=True),
                                Column('key', String, nullable=False))
        self.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def store_key(self, key_name, key):
        session = self.Session()
        try:
            stmt = insert(self.keys_table).values(key_name=key_name, key=key)
            stmt = stmt.on_conflict_do_update(
                index_elements=['key_name'], 
                set_=dict(key=key)
            )
            session.execute(stmt)
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def retrieve_key(self, key_name):
        session = self.Session()
        try:
            result = session.execute(self.keys_table.select().where(self.keys_table.c.key_name == key_name)).fetchone()
            if result:
                return result[1]
            else:
                raise KeyError(f'Key {key_name} not found')
        finally:
            session.close()