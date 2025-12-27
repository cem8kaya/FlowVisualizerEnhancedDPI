#!/bin/bash

# Clear sessions and events from the database
DB_PATH="$(dirname "$0")/../db/callflowd.db"

if [ -f "$DB_PATH" ]; then
    echo "Database file found at: $DB_PATH"
else
    echo "Database file not found at: $DB_PATH"
    # Try looking in current directory
    if [ -f "callflowd.db" ]; then
        DB_PATH="callflowd.db"
    fi
fi

echo "Clearing sessions from $DB_PATH..."
sqlite3 "$DB_PATH" "DELETE FROM jobs;"
sqlite3 "$DB_PATH" "DELETE FROM events;"
sqlite3 "$DB_PATH" "DELETE FROM sessions;"
sqlite3 "$DB_PATH" "VACUUM;"

echo "Database sessions cleared."
