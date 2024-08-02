// pages/api/login.js

import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect();

export default async function handler(req, res) {
  console.log('Handler invoked');
  
  if (req.method !== 'POST') {
    console.log('Method not allowed');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    console.log('POST request received');
    const { username, password } = req.body;

    const dbRes = await client.query('SELECT * FROM tbl_users WHERE username = $1', [username]);

    if (dbRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = dbRes.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({ message: 'Login successful', user, token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
