import sqlite3
from key_manager import KeyManager

class SQLiteKeyManager(KeyManager):
    def __init__(self, db_path=':memory:'):
        self.conn = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS keys (
                    key_name TEXT PRIMARY KEY,
                    key TEXT NOT NULL
                )
            ''')

    def store_key(self, key_name, key):
        with self.conn:
            self.conn.execute('''
                INSERT OR REPLACE INTO keys (key_name, key)
                VALUES (?, ?)
            ''', (key_name, key))

    def retrieve_key(self, key_name):
        cursor = self.conn.execute('''
            SELECT key FROM keys WHERE key_name = ?
        ''', (key_name,))
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            raise KeyError(f'Key {key_name} not found')