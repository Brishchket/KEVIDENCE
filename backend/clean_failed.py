import sqlite3

def clean_failed():
    conn = sqlite3.connect('phantompatch.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM narratives WHERE faithfulness_score = 0.0")
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    print(f"Deleted {deleted} failed narratives.")

if __name__ == '__main__':
    clean_failed()
