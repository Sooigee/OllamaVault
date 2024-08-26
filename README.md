# OllamaVault

## Overview

OllamaVault is a strong front-end proxy solution. It creates a safe connection between your clients and the Ollama AI model server. OllamaVault checks API keys and directs requests effectively. It acts as a gatekeeper for your AI models, making sure only authorized users can access them.

### NOTE: THIS IS MADE FOR LINUX ON UBUNTU

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

Or when running in the server cli, run rs
```

### Commands


#### addkey
 - Description: Generates a manual new API key and adds it to the list of authorized keys.
 Use this command to allow access to the server with a new API key. NOT SECURE.

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
