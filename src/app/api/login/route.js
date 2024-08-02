// app/api/login/route.js

import { NextResponse } from "next/server";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

client.connect().catch(err => {
  console.error('Database connection error:', err );
});

export async function POST(request) {
  try {
    console.log('POST request received');
    const { username, password } = await request.json();
    console.log(`Received data - Username: ${username}, Password: ${password}`);

    if (!username || !password) {
      console.log('Missing username or password');
      return new Response(JSON.stringify({ error: 'Username and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const dbRes = await client.query('SELECT * FROM tbl_users WHERE username = $1', [username]);
    console.log('Database query executed');

    if (dbRes.rows.length === 0) {
      console.log('User not found');
      return new Response(JSON.stringify({ error: 'User not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const user = dbRes.rows[0];
    console.log(`User found: ${JSON.stringify(user)}`);

    const match = await bcrypt.compare(password, user.password);
    console.log(`Password match: ${match}`);

    if (!match) {
      console.log('Invalid password');
      return new Response(JSON.stringify({ error: 'Invalid password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`JWT token generated: ${token}`);

    return new Response(JSON.stringify({ message: 'Login successful', user, token }), {
      status: 200,
      headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error:', error);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
    });
  }
}
