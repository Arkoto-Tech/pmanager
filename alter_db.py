import sqlite3

conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE credentials ADD COLUMN site_username TEXT DEFAULT ''")
    print("Added column 'site_username'.")
except Exception as e:
    print("Column 'site_username' may already exist or an error occurred:", e)

try:
    cursor.execute("ALTER TABLE credentials ADD COLUMN site_password TEXT DEFAULT ''")
    print("Added column 'site_password'.")
except Exception as e:
    print("Column 'site_password' may already exist or an error occurred:", e)

try:
    cursor.execute("ALTER TABLE credentials ADD COLUMN user_id TEXT DEFAULT ''")
    print("Added column 'user_id'.")
except Exception as e:
    print("Column 'user_id' may already exist or an error occurred:", e)

conn.commit()
conn.close()
print("Database schema updated successfully!")
