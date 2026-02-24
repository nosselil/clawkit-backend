const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const nacl = require('tweetnacl');
const bs58 = require('bs58');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// CORS Middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://lenovo-dashboard.netlify.app',
    'https://clawkit.net'
  ];
  
  if (!origin || allowedOrigins.includes(origin) || origin?.includes('netlify.app')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Solana Wallet auth
app.post('/api/auth/wallet', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  try {
    const { publicKey, signature, message } = req.body;

    if (!publicKey || !signature || !message) {
      return res.status(400).json({ error: 'Missing publicKey, signature, or message' });
    }

    // Verify the signature
    let isValid = false;
    try {
      const publicKeyBytes = bs58.decode(publicKey);
      const signatureBytes = bs58.decode(signature);
      const messageBytes = Buffer.from(message, 'utf-8');

      isValid = nacl.sign.detached.verify(
        messageBytes,
        signatureBytes,
        publicKeyBytes
      );
    } catch (err) {
      console.error('Signature verification error:', err);
      return res.status(401).json({ error: 'Invalid signature format' });
    }

    if (!isValid) {
      return res.status(401).json({ error: 'Signature verification failed' });
    }

    // Signature is valid - return JWT
    const payload = {
      id: uuidv4(),
      walletAddress: publicKey,
      provider: 'solana',
      createdAt: new Date().toISOString(),
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        walletAddress: publicKey,
        provider: 'solana',
      },
    });
  } catch (error) {
    console.error('Wallet auth error:', error);
    res.status(500).json({ error: 'Wallet connection failed' });
  }
});

module.exports = app;
