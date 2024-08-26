# OllamaKeyGuard

## Overview

OllamaKeyGuard is a powerful frontend proxy solution designed to provide a secure interface between your clients and the Ollama AI model server. By enforcing strict API key validation and efficiently routing requests, OllamaKeyGuard acts as a gatekeeper to your AI models, ensuring that only authenticated users gain access.

## Key Features

- API Key Management: Generate, validate, and manage API keys effortlessly to control access to your Ollama server.
- Secure Proxying: Safeguard your AI models by routing all incoming requests through a secure proxy, filtering out unauthorized access.
- Streaming Response Handling: Handle streaming AI responses from Ollama in real-time, ensuring smooth and continuous data flow for applications like chatbots or live data analysis tools.
- Comprehensive Error Handling: Robust error detection and handling, providing clear messages when issues like server downtime or unexpected data formats occur.
- Flexible Routing: Supports a broad range of API endpoints, rerouting them appropriately to the Ollama backend.

## Use Cases

- API Gateway: Use OllamaKeyGuard as a secure gateway to manage and control access to your Ollama AI models.
- Security Layer: Implement OllamaKeyGuard to add an extra security layer to your AI-driven applications, ensuring that only valid requests are processed.
- Real-time AI Applications: Perfect for scenarios requiring continuous data streams, such as AI-powered chatbots or live data analysis tools.

## Getting Started

1. Clone the Repository:
```
git clone https://github.com/Sooigee/OllamaKeyGuard.git
cd OllamaKeyGuard
```
2. Install Dependencies:
```
npm install express axios morgan body-parser
```
3. Configure API Keys:

   Set up your API keys using the provided command-line interface or configuration files.

4. Run the Server:
```
node server.js
```
   The server will start at http://localhost:3000, ready to manage and route your requests securely.
