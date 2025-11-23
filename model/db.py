from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from datetime import datetime
import os

# MongoDB connection string from the user
MONGO_URI = "mongodb+srv://johanvega01_db_user:CmMw8mO4ow2ehjh5@cluster0.pyavozq.mongodb.net/?appName=Cluster0"

client = None
db = None

def init_db():
    """Initializes the MongoDB connection."""
    global client, db
    try:
        client = MongoClient(MONGO_URI)
        client.admin.command('ping') # Test connection
        db = client.jwt_history # database name
        print("MongoDB connection successful!")
        print(f"DB object after successful connection: {db}")
    except ConnectionFailure as e:
        print(f"MongoDB connection failed: {e}")
        client = None
        db = None
        print(f"DB object after failed connection: {db}")

def save_result(jwt_string, analysis_result):
    """Saves a JWT analysis result to the database."""
    if db is not None:
        try:
            history_collection = db.history # collection name
            record = {
                "jwt_string": jwt_string,
                "analysis_result": analysis_result,
                "timestamp": datetime.utcnow()
            }
            history_collection.insert_one(record)
            print("Analysis result saved to MongoDB.")
            return True
        except Exception as e:
            print(f"Error saving result to MongoDB: {e}")
            return False
    else:
        print(f"Debug: db is None in save_result. Current db: {db}")
        print("Database not initialized. Cannot save result.")
        return False

def get_history():
    """Retrieves all JWT analysis history from the database."""
    if db is not None:
        try:
            history_collection = db.history
            # Fetch all documents, sort by timestamp in descending order
            history_data = list(history_collection.find().sort("timestamp", -1))
            # Convert ObjectId to string for JSON serialization
            for record in history_data:
                record['_id'] = str(record['_id'])
            print("Retrieved JWT analysis history.")
            return history_data
        except Exception as e:
            print(f"Error retrieving history from MongoDB: {e}")
            return []
    else:
        print(f"Debug: db is None in get_history. Current db: {db}")
        print("Database not initialized. Cannot retrieve history.")
        return []
