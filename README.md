# OllamaVault

## Overview

OllamaVault is a powerful frontend proxy solution designed to provide a secure interface between your clients and the Ollama AI model server. By enforcing strict API key validation and efficiently routing requests, OllamaVault is a gatekeeper to your AI models, ensuring that only authenticated users gain access. 

### NOTE: THIS IS MADE FOR LINUX ON UBUNTU

## Key Features

- API Key Management: Generate, validate, and manage API keys effortlessly to control access to your Ollama server.
- Secure Proxying: Safeguard your AI models by routing all incoming requests through a secure proxy, filtering out unauthorized access.
- Streaming Response Handling: Handle streaming AI responses from Ollama in real-time, ensuring smooth and continuous data flow for applications like chatbots or live data analysis tools.
- Comprehensive Error Handling: Robust error detection and handling, providing clear messages when issues like server downtime or unexpected data formats occur.
- Flexible Routing: Supports a broad range of API endpoints, rerouting them appropriately to the Ollama backend.

## Use Cases

- API Gateway: Use OllamaVault as a secure gateway to manage and control access to your Ollama AI models.
- Security Layer: Implement OllamaVault to add an extra security layer to your AI-driven applications, ensuring that only valid requests are processed.
- Real-time AI Applications: Perfect for scenarios requiring continuous data streams, such as AI-powered chatbots or live data analysis tools.

## Getting Started

1. Clone the Repository:
```
git clone https://github.com/Sooigee/OllamaVault.git
cd OllamaVault
```

2. Install Dependencies:
```
npm install express axios morgan body-parser nodemon
```

3. Run the Server:
```
npx nodemon server.js
```
   The server will start at http://localhost:3000, you can change this at ``` const ollamaServerUrl = 'http://localhost:11434'; ``` and ``` const port = 3000; ``` .


4. Configure API Keys:

   Set up your API keys using the provided command-line interface.  
   

5. Problems:
If you ever experience any problems such as file perms failing, run these commands in that directory

```
sudo chown -R yourusername:yourusername /path/to/folder

sudo chmod -R u+rw /path/to/folder
```

### Commands


#### addkey
 - Description: Generates a manual new API key and adds it to the list of authorized keys.
 Use this command to allow access to the server with a new API key.

#### generatekey
- Description: Creates a new secure API key adding it to the authorized list.
Use this command to allow access to the server with a new API key.

#### removekey <API_KEY>
- Description: Removes a specified API key from the list of authorized keys.
This command is used to revoke access to the server for a specific key.

#### listkeys
- Description: Displays all currently authorized API keys.
Use this command to view which keys have access to the server.

#### setratelimit <max_requests> <time_window_in_seconds>
- Description: Configures the rate limiting settings.
You can set the maximum number of requests allowed in a specified time window.

#### enableratelimit
- Description: Enables rate limiting based on the current configuration.
If rate limiting is disabled, this command will activate it.

#### disableratelimit
- Description: Disables rate limiting.
Useful if you need to temporarily allow unlimited requests to the server.
