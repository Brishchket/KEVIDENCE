import sqlite3

def clean_mock():
    conn = sqlite3.connect('phantompatch.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM narratives WHERE provider = 'mock'")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Deleted {deleted} mock narratives.")

if __name__ == '__main__':
    clean_mock()
