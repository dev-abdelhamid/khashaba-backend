import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/clinic';
const ADMIN_ID = '689816f1c4117ace94016977';
const ADMIN_USERNAME = 'dr-mohamed';
const ADMIN_PASSWORD = 'drmohamed2025';

async function updateAdminPassword() {
  try {
    // Connect to MongoDB
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');

    // Define Admin schema
    const adminSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true, trim: true },
      password: { type: String, required: true },
      createdAt: { type: Date, default: Date.now }
    });
    const Admin = mongoose.model('Admin', adminSchema);

    // Hash the password
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);

    // Update or create admin
    const result = await Admin.updateOne(
      { _id: new mongoose.Types.ObjectId(ADMIN_ID) },
      { $set: { username: ADMIN_USERNAME, password: hashedPassword } },
      { upsert: true } // Create if not exists
    );

    if (result.matchedCount > 0) {
      console.log('Admin password updated successfully');
    } else if (result.upsertedCount > 0) {
      console.log('Admin user created with hashed password');
    } else {
      console.log('No changes made to admin user');
    }

  } catch (error) {
    console.error('Full error:', error);
  } finally {
    // Close the connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

updateAdminPassword();