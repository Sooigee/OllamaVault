# OllamaVault

## Overview

OllamaVault is a secure API proxy server for Ollama, providing API key management and rate limiting functionality. It allows you to safely expose your Ollama server while maintaining control over access and usage.

## Note

This application has been developed and tested on Linux systems. While it may work on other operating systems, its functionality on non-Linux platforms has not been verified. Use on other systems at your own discretion.

## Features

- API key management (add, remove, generate, list)
- Key labeling for easy identification
- Rate limiting with configurable settings
- Encrypted storage of API keys and labels
- Simple CLI for management operations

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Sooigee/OllamaVault.git
   cd OllamaVault
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```


3. Run the server:
   ```
   python3 OllamaVault.py
   ```

## Usage

Once the server is running, you can use the following commands in the CLI:

- `addkey <key>`: Add a new API key
- `generatekey`: Generate a new API key
- `removekey <key>`: Remove an existing API key
- `listkeys`: List all API keys
- `labelkey <key> <label>`: Add a label to an API key
- `removelabel <key>`: Remove the label from an API key
- `setratelimit <max_requests> <time_window_in_seconds>`: Set rate limit
- `enableratelimit`: Enable rate limiting
- `disableratelimit`: Disable rate limiting
- `ratelimitstatus`: Check current rate limit status
- `exit`: Shut down the server

## Making Requests

To make requests to your Ollama server through OllamaVault, use the following URL format:

```
http://localhost:3000/api/generate
```

Include your API key in the Authorization header:

```
Authorization: Bearer YOUR_API_KEY
```

