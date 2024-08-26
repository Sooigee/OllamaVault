const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
const port = 3000;
const apikeysFile = path.join(__dirname, 'apikeys.json');
const ollamaServerUrl = 'http://localhost:11434';

// Encryption settings (fixed key and IV for consistency)
const algorithm = 'aes-256-cbc';
const secretKey = crypto.createHash('sha256').update('your_secret_key').digest();
const iv = crypto.createHash('sha256').update('your_iv').digest().slice(0, 16); // Generate a 16-byte IV

// Middleware to parse JSON bodies and log requests
app.use(bodyParser.json());
app.use(morgan('combined'));

// Function to encrypt data
function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return encrypted.toString('hex');
}

// Function to decrypt data
function decrypt(text) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(text, 'hex')), decipher.final()]);
    return decrypted.toString();
}

// Function to load API keys from the encrypted JSON file
function loadApiKeys() {
    if (fs.existsSync(apikeysFile)) {
        const encryptedData = fs.readFileSync(apikeysFile, 'utf8');
        const decryptedData = decrypt(encryptedData);
        return new Set(JSON.parse(decryptedData));
    }
    return new Set();
}

// Function to save API keys to the encrypted JSON file
function saveApiKeys(apiKeys) {
    const dataToEncrypt = JSON.stringify([...apiKeys]);
    const encryptedData = encrypt(dataToEncrypt);
    fs.writeFileSync(apikeysFile, encryptedData, 'utf8');
}

// Load existing API keys
const apiKeys = loadApiKeys();

// Function to generate a SHA-256 API key
function generateApiKey() {
    return crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');
}

// CLI commands for managing API keys
function handleCommand(command, args) {
    switch (command) {
        case 'addkey':
            if (args.length < 1) {
                console.log('Error: You must provide a key to add.');
                return;
            }
            const keyToAdd = args[0];
            if (apiKeys.has(keyToAdd)) {
                console.log('Error: Key already exists.');
            } else {
                apiKeys.add(keyToAdd);
                saveApiKeys(apiKeys);
                console.log(`API key added: ${keyToAdd}`);
            }
            break;
        
        case 'generatekey':
            const newKey = generateApiKey();
            apiKeys.add(newKey);
            saveApiKeys(apiKeys);
            console.log(`Generated API key: ${newKey}`);
            break;

        case 'removekey':
            if (args.length < 1) {
                console.log('Error: You must provide a key to remove.');
                return;
            }
            const keyToRemove = args[0];
            if (apiKeys.delete(keyToRemove)) {
                saveApiKeys(apiKeys);
                console.log(`API key removed: ${keyToRemove}`);
            } else {
                console.log('Error: Key not found.');
            }
            break;

        case 'listkeys':
            if (apiKeys.size === 0) {
                console.log('No API keys available.');
            } else {
                console.log('API Keys:');
                apiKeys.forEach(key => console.log(key));
            }
            break;

        default:
            console.log('Unknown command. Available commands: addkey, generatekey, removekey, listkeys');
    }
}

// Set up readline interface for in-process command handling
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.on('line', (input) => {
    const [command, ...args] = input.trim().split(' ');
    handleCommand(command, args);
});

// Define routes to be rerouted to /api/tags on Ollama server
const routes = [
    '/api/tags', '/api/models', '/v1/models', '/models', '/tags', 
    '/v1/tags', '/api/v1/models', '/v1/api/models'
];

routes.forEach(route => {
    app.get(route, async (req, res) => {
        try {
            const response = await axios.get(`${ollamaServerUrl}/api/tags`);
            res.json(response.data);
        } catch (error) {
            if (error.code === 'ECONNREFUSED') {
                res.status(503).json({ error: 'Ollama server is offline or unreachable' });
            } else {
                res.status(500).json({ error: 'Failed to retrieve tags from Ollama server' });
            }
            console.error(`Error on ${route}:`, error);
        }
    });
});

// Middleware to check for a valid API key for protected routes
app.use('/api/generate', (req, res, next) => {
    console.log('Request Headers:', req.headers);
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'API key is required' });
    }

    const token = authHeader.split(' ')[1];
    console.log('Token:', token);

    if (!apiKeys.has(token)) {
        return res.status(403).json({ error: 'Invalid API key' });
    }

    next();
});

// Route to interface with the Ollama server for generating models
app.post('/api/generate', async (req, res) => {
    const { prompt, model } = req.body;

    if (!prompt || !model) {
        return res.status(400).json({ error: 'Prompt and model are required' });
    }

    try {
        const responseStream = await axios({
            method: 'post',
            url: `${ollamaServerUrl}/api/generate`,
            data: { prompt, model },
            responseType: 'stream',
        });

        // Stream the response chunks from Ollama server directly to the client
        responseStream.data.pipe(res);

    } catch (error) {
        if (error.code === 'ECONNREFUSED') {
            res.status(503).json({ error: 'Ollama server is offline or unreachable' });
        } else if (error.response && error.response.data) {
            res.status(500).json({ error: error.response.data });
        } else {
            res.status(500).json({ error: 'Failed to generate response from model' });
        }
        console.error('Error communicating with Ollama server:', error);
    }
});

// Start the server
app.listen(port, () => {
    console.log(`API server running on http://localhost:${port}`);
    console.log('Enter commands below (addkey, generatekey, removekey, listkeys):');
});
