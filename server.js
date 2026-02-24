import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

// Load environment variables from .env file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// CORS Middleware - explicitly set headers
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://lenovo-dashboard.netlify.app',
    'https://clawkit.net'
  ];
  
  if (!origin || allowedOrigins.includes(origin) || origin.includes('netlify.app')) {
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

// Mock user database (in production, use real DB)
const users = new Map();

// Utility functions
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

const verifyJWT = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Get current user
app.get('/api/auth/me', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  res.json(decoded);
});

// Google OAuth - Step 1: Redirect to Google
app.get('/api/auth/google', (req, res) => {
  const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  
  const redirectUri = process.env.REDIRECT_URI_DEV || 'http://localhost:5173/auth/callback';
  
  googleAuthUrl.searchParams.append('client_id', process.env.GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.append('redirect_uri', redirectUri);
  googleAuthUrl.searchParams.append('response_type', 'code');
  googleAuthUrl.searchParams.append('scope', 'openid email profile');
  googleAuthUrl.searchParams.append('access_type', 'offline');
  
  res.redirect(googleAuthUrl.toString());
});

// Google OAuth - Step 2: Handle callback and exchange code
app.post('/api/auth/callback/google', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Missing authorization code' });
    }

    // Exchange code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: process.env.REDIRECT_URI_DEV || 'http://localhost:5173/auth/callback',
    });

    const { access_token, id_token } = tokenResponse.data;

    // Get user info from Google
    const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const { email, name, picture } = userResponse.data;

    // Create or get user
    let user = Array.from(users.values()).find(u => u.email === email && u.provider === 'google');
    
    if (!user) {
      const userId = uuidv4();
      user = {
        id: userId,
        username: name || email.split('@')[0],
        email,
        provider: 'google',
        picture,
        createdAt: new Date().toISOString(),
      };
      users.set(userId, user);
    }

    const token = generateJWT(user);
    const apiKey = generateAPIKey(user.id);

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email,
        provider: 'google',
        picture,
      },
      apiKey,
    });
  } catch (error) {
    console.error('Google OAuth callback error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// GitHub OAuth - Step 1: Redirect to GitHub
app.get('/api/auth/github', (req, res) => {
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
  
  const redirectUri = process.env.REDIRECT_URI_DEV || 'http://localhost:5173/auth/callback';
  
  githubAuthUrl.searchParams.append('client_id', process.env.GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.append('redirect_uri', redirectUri);
  githubAuthUrl.searchParams.append('scope', 'read:user user:email');
  
  res.redirect(githubAuthUrl.toString());
});

// GitHub OAuth - Step 2: Handle callback and exchange code
app.post('/api/auth/callback/github', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Missing authorization code' });
    }

    // Exchange code for access token
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }, {
      headers: { Accept: 'application/json' },
    });

    const { access_token } = tokenResponse.data;

    if (!access_token) {
      throw new Error('Failed to get access token');
    }

    // Get user info from GitHub
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: { 
        Authorization: `Bearer ${access_token}`,
        Accept: 'application/vnd.github.v3+json',
      },
    });

    const { login: username, avatar_url } = userResponse.data;
    
    // Get email from GitHub
    let email = userResponse.data.email;
    if (!email) {
      try {
        const emailResponse = await axios.get('https://api.github.com/user/emails', {
          headers: {
            Authorization: `Bearer ${access_token}`,
            Accept: 'application/vnd.github.v3+json',
          },
        });
        const primaryEmail = emailResponse.data.find(e => e.primary);
        email = primaryEmail?.email || `${username}@github.com`;
      } catch (emailErr) {
        email = `${username}@github.com`;
      }
    }

    // Create or get user
    let user = Array.from(users.values()).find(u => u.email === email && u.provider === 'github');
    
    if (!user) {
      const userId = uuidv4();
      user = {
        id: userId,
        username,
        email,
        provider: 'github',
        avatar: avatar_url,
        createdAt: new Date().toISOString(),
      };
      users.set(userId, user);
    }

    const token = generateJWT(user);
    const apiKey = generateAPIKey(user.id);

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email,
        provider: 'github',
        avatar: user.avatar,
      },
      apiKey,
    });
  } catch (error) {
    console.error('GitHub OAuth callback error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// OPTIONS handler for wallet endpoint (preflight)
app.options('/api/auth/wallet', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// Solana Wallet auth
app.post('/api/auth/wallet', (req, res) => {
  // Set CORS headers explicitly
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
      const messageBytes = new TextEncoder().encode(message);

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

    res.json({
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
});

// Generate API key
app.post('/api/keys/generate', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  const apiKey = generateAPIKey(decoded.id);
  res.json({ apiKey, userId: decoded.id });
});

// Test endpoint
app.post('/api/test', (req, res) => {
  res.json({ message: 'API is working', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server locally (when not on Vercel)
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 ClawKit API Server running on http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Export handler for Vercel serverless
// Vercel calls this with (req, res) parameters
const handler = app;
export default handler;
