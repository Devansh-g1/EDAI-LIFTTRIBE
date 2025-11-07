#!/usr/bin/env python3
"""
MongoDB Connection Test Script
Run this to test your MongoDB Atlas connection before deployment
"""

import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def test_mongodb_connection():
    """Test MongoDB connection and basic operations"""
    
    mongo_url = os.environ.get('MONGO_URL')
    db_name = os.environ.get('DB_NAME', 'cryptogig_db')
    
    if not mongo_url or mongo_url == 'your_new_mongodb_connection_string_here':
        print("❌ MONGO_URL not set or using placeholder value")
        print("Please update your .env file with a valid MongoDB Atlas connection string")
        return False
    
    print(f"🔍 Testing connection to: {mongo_url[:50]}...")
    
    try:
        # Create client
        client = AsyncIOMotorClient(mongo_url)
        
        # Test connection
        await client.admin.command('ping')
        print("✅ Successfully connected to MongoDB!")
        
        # Get database
        db = client[db_name]
        
        # Test database operations
        print(f"📊 Testing database: {db_name}")
        
        # List collections
        collections = await db.list_collection_names()
        print(f"📁 Existing collections: {collections}")
        
        # Test write operation
        test_collection = db.test_connection
        result = await test_collection.insert_one({
            "test": True,
            "timestamp": "2024-01-01T00:00:00Z",
            "message": "Connection test successful"
        })
        print(f"✅ Test document inserted with ID: {result.inserted_id}")
        
        # Test read operation
        document = await test_collection.find_one({"_id": result.inserted_id})
        print(f"✅ Test document retrieved: {document}")
        
        # Clean up test document
        await test_collection.delete_one({"_id": result.inserted_id})
        print("🧹 Test document cleaned up")
        
        # Close connection
        client.close()
        print("✅ MongoDB connection test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("\n🔧 Troubleshooting tips:")
        print("1. Check your MongoDB Atlas connection string")
        print("2. Ensure your IP address is whitelisted (0.0.0.0/0 for all)")
        print("3. Verify database user credentials")
        print("4. Check if the cluster is running")
        return False

if __name__ == "__main__":
    print("🧪 MongoDB Connection Test")
    print("=" * 30)
    
    success = asyncio.run(test_mongodb_connection())
    
    if success:
        print("\n🎉 Your MongoDB setup is ready for deployment!")
    else:
        print("\n💡 Please fix the MongoDB connection issues before deploying")
        exit(1)