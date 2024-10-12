import sqlite3

def initialize_db():
    # تحديد اسم ملف قاعدة البيانات
    conn = sqlite3.connect('network_monitor.db')
    cursor = conn.cursor()

    # إنشاء الجداول
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        size INTEGER NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS SourceIPs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        count INTEGER NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        packet_id INTEGER,
        description TEXT,
        FOREIGN KEY (packet_id) REFERENCES Packets(id)
    )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    initialize_db()
