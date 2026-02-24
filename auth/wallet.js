import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Mock user database
const users = new Map();

const generateJWT = (userData) => {
  const payload = {
    id: userData.id,
    username: userData.username,
    provider: userData.provider,
    email: userData.email,
    createdAt: new Date().toISOString(),
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
};

const generateAPIKey = (userId) => {
  const timestamp = Date.now();
  const randomPart = uuidv4().replace(/-/g, '').substring(0, 8);
  return `clk_${userId.substring(0, 8)}_${timestamp}_${randomPart}`;
};

// CORS headers helper
const setCorsHeaders = (req, res) => {
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
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
};

export default function handler(req, res) {
  // Set CORS headers
  setCorsHeaders(req, res);
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

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

    // Signature is valid - create or get user
    let user = Array.from(users.values()).find(
      (u) => u.walletAddress === publicKey && u.provider === 'solana'
    );

    if (!user) {
      const userId = uuidv4();
      user = {
        id: userId,
        username: publicKey.substring(0, 8),
        email: `${publicKey}@solana.local`,
        provider: 'solana',
        walletAddress: publicKey,
        createdAt: new Date().toISOString(),
      };
      users.set(userId, user);
    }

    const token = generateJWT(user);
    const apiKey = generateAPIKey(user.id);

    res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        provider: 'solana',
        walletAddress: user.walletAddress,
      },
      apiKey,
    });
  } catch (error) {
    console.error('Wallet auth error:', error);
    res.status(500).json({ error: 'Wallet connection failed' });
  }
}
