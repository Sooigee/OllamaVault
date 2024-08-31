import os, json, hashlib, secrets, time, signal, threading, base64, logging, atexit, uuid, requests, subprocess
from functools import wraps
from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from gunicorn.app.base import BaseApplication
from multiprocessing import Value, Lock, Manager
from multiprocessing.util import _exit_function


# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask app creation
app = Flask(__name__)

# Configuration
class Config:
    PORT = int(os.getenv('PORT', 3000))
    OLLAMA_SERVER_URL = os.getenv('OLLAMA_SERVER_URL', 'http://127.0.0.1:11434')
    DISPLAY_DEBUG_INFO = False

app.config.from_object(Config)
ddi = Config.DISPLAY_DEBUG_INFO


class SharedRateLimiter:
    def __init__(self):
        self.manager = Manager()
        self.enabled = Value('b', True)
        self.max_requests = Value('i', 500)
        self.window_seconds = Value('i', 300)
        self.requests = self.manager.dict()
        self.last_reset = self.manager.dict()
        self.lock = Lock()

    def update_settings(self, enabled, max_requests, window_seconds):
        with self.lock:
            self.enabled.value = enabled
            self.max_requests.value = max_requests
            self.window_seconds.value = window_seconds
            self.requests.clear()
            self.last_reset.clear()

    def limit(self):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                with self.lock:
                    if not self.enabled.value:
                        return f(*args, **kwargs)

                    now = time.time()
                    ip = request.remote_addr

                    if ip not in self.requests:
                        self.requests[ip] = 0
                        self.last_reset[ip] = now

                    if now - self.last_reset[ip] > self.window_seconds.value:
                        self.requests[ip] = 0
                        self.last_reset[ip] = now

                    if self.requests[ip] >= self.max_requests.value:
                        return jsonify({"error": "Rate limit exceeded"}), 429

                    self.requests[ip] += 1

                return f(*args, **kwargs)
            return wrapped
        return decorator

rate_limiter = SharedRateLimiter()

def get_machine_id():
    # Get a unique identifier for the machine.
    try:
        with open('/etc/machine-id', 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return str(uuid.uuid4())

MACHINE_ID = get_machine_id()

def derive_key(salt):
 # Derive a key using scrypt KDF.
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(MACHINE_ID.encode())

def encrypt(data):
# Encrypt data using AES-GCM.
    salt = os.urandom(16)
    key = derive_key(salt)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    if isinstance(data, set):
        data = list(data)
    ciphertext = encryptor.update(json.dumps(data).encode()) + encryptor.finalize()
    encrypted = salt + iv + encryptor.tag + ciphertext
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(encrypted_data):
# Decrypt data using AES-GCM.
    try:
        encrypted = base64.b64decode(encrypted_data)
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise ValueError("Failed to decode the encrypted data.")

    salt, iv, tag, ciphertext = (
        encrypted[:16],
        encrypted[16:28],
        encrypted[28:44],
        encrypted[44:]
    )
    key = derive_key(salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(data.decode())


api_keys = set()
key_labels = {}

def save_api_keys():
    apikeys_file = 'apikeys.json'
    try:
        encrypted_data = encrypt(list(api_keys))
        with open(apikeys_file, 'w') as f:
            f.write(encrypted_data)
        logger.info(f"API keys saved successfully. Number of keys: {len(api_keys)}")
        load_api_keys() 
    except Exception as e:
        logger.error(f"Error saving API keys: {e}")



def load_api_keys():
    global api_keys
    apikeys_file = 'apikeys.json'
    if os.path.exists(apikeys_file):
        try:
            with open(apikeys_file, 'rb') as f:
                encrypted_data = f.read()
            if not encrypted_data:
                if ddi:
                    logger.warning("API keys file is empty.")
                return
            loaded_keys = decrypt(encrypted_data)
            api_keys = set(loaded_keys)
        except Exception as e:
            logger.error(f"Error loading API keys: {e}")
    else:
        if ddi:
            logger.warning("API keys file does not exist.")

def save_labels():
    labels_file = 'key_labels.json'
    try:
        encrypted_data = encrypt(key_labels) 
        with open(labels_file, 'w') as f:
            f.write(encrypted_data)
        logger.info("Key labels saved successfully.")
    except Exception as e:
        logger.error(f"Error saving key labels: {e}")

def load_labels():
    global key_labels
    labels_file = 'key_labels.json'
    if os.path.exists(labels_file):
        try:
            with open(labels_file, 'r') as f:
                encrypted_data = f.read()
            key_labels = decrypt(encrypted_data) 
        except Exception as e:
            logger.error(f"Error loading key labels: {e}")
    else:
        if ddi:
            logger.warning("Key labels file is empty.")


# Function to generate a SHA-256 API key
def generate_api_key():
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

# Function to load settings from the JSON file
def load_settings():
    settings_file = 'settings.json'
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            settings = json.load(f)
        logger.info(f"Loaded settings: {settings}")
        return settings
    else:
        default_settings = {
            'rate_limit_enabled': True,
            'max_requests': 500,
            'window_seconds': 300 
        }
        if ddi:
            logger.info(f"Using default settings: {default_settings}")

        return default_settings

# Function to save settings to the JSON file
def save_settings(settings):
    settings_file = 'settings.json'
    try:
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        logger.info(f"Settings saved successfully: {settings}")
    except Exception as err:
        logger.error(f'Error saving settings: {err}')

# Load initial settings
settings = load_settings()
rate_limiter.update_settings(
    settings['rate_limit_enabled'],
    settings['max_requests'],
    settings['window_seconds']
)

def load_api_keys_directly():
    apikeys_file = 'apikeys.json'
    if os.path.exists(apikeys_file):
        try:
            with open(apikeys_file, 'rb') as f:
                encrypted_data = f.read()
            if encrypted_data:
                return set(decrypt(encrypted_data))
            else:
                return set()
        except Exception as e:
            logger.error(f"Error loading API keys: {e}")
            return set()
    return set()

@app.route('/')
def home():
    return "Welcome to the OllamaVault API proxy server!"

@app.route('/api/tags')
@app.route('/api/models')
@app.route('/v1/models')
@app.route('/models')
@app.route('/tags')
@app.route('/v1/tags')
@app.route('/api/v1/models')
@app.route('/v1/api/models')
@rate_limiter.limit()
def proxy_to_ollama_tags():
    try:
        response = requests.get(f'{Config.OLLAMA_SERVER_URL}/api/tags')
        return Response(response.content, status=response.status_code, content_type=response.headers['Content-Type'])
    except requests.RequestException as e:
        logger.error(f'Failed to retrieve tags from Ollama server: {str(e)}')
        return jsonify({'error': 'Failed to retrieve tags from Ollama server'}), 500

@app.route('/api/generate', methods=['POST'])
@rate_limiter.limit()
def generate():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Unauthorized'}), 401

    provided_key = auth_header.split(' ')[1].strip()

    current_api_keys = load_api_keys_directly()

    if provided_key not in current_api_keys:
        logger.error(f"Unauthorized access attempt with key: {provided_key}")
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        response = requests.post(f'{Config.OLLAMA_SERVER_URL}/api/generate', json=request.json, stream=True)
        return Response(response.iter_content(chunk_size=8192), status=response.status_code, content_type=response.headers['Content-Type'])
    except requests.RequestException as e:
        logger.error(f'Failed to generate response from Ollama server: {str(e)}')
        return jsonify({'error': 'Failed to generate response from Ollama server'}), 500

def handle_command(command, args):
    global api_keys, key_labels
    command_executed = False

    if command == 'addkey':
        command_executed = True
        if len(args) < 1:
            logger.error('Error: You must provide a key to add.')
        else:
            key_to_add = args[0].strip()
            if key_to_add in api_keys:
                logger.error('Error: Key already exists.')
            else:
                api_keys.add(key_to_add)
                save_api_keys()  
                load_api_keys()   
                logger.info(f'API key added: {key_to_add}')

    elif command == 'removekey':
        command_executed = True
        if len(args) < 1:
            logger.error('Error: You must provide a key to remove.')
        else:
            key_to_remove = args[0].strip()
            if key_to_remove in api_keys:
                api_keys.remove(key_to_remove)
                save_api_keys()  
                load_api_keys()  
                logger.info(f'API key removed: {key_to_remove}')
            else:
                logger.error('Error: Key not found.')

    elif command == 'generatekey':
        command_executed = True
        new_key = generate_api_key().strip()
        api_keys.add(new_key)
        save_api_keys()   
        load_api_keys()   
        logger.info(f'Generated new API key: {new_key}')

    elif command == 'listkeys':
        command_executed = True
        if not api_keys:
            logger.info('No API keys available.')
        else:
            logger.info('API Keys:')
            for key in api_keys:
                label = key_labels.get(key, "")
                logger.info(f'{key}  {{{label}}}' if label else key)

    elif command == 'labelkey':
        command_executed = True
        if len(args) < 2:
            logger.error('Error: You must provide both a key and a label.')
        else:
            key = args[0]
            label = ' '.join(args[1:])
            if key in api_keys:
                key_labels[key] = label
                save_labels()
                logger.info(f'Label added to key: {key}  {{{label}}}')
            else:
                logger.error('Error: Key not found.')

    elif command == 'removelabel':
        command_executed = True
        if len(args) < 1:
            logger.error('Error: You must provide a key to remove the label from.')
        else:
            key = args[0]
            if key in key_labels:
                del key_labels[key]
                save_labels()
                logger.info(f'Label removed from key: {key}')
            else:
                logger.error('Error: No label found for this key.')

    elif command == 'setratelimit':
        command_executed = True
        if len(args) < 2:
            logger.error('Error: You must provide both max requests and time window in seconds.')
        else:
            try:
                max_requests = int(args[0])
                window_seconds = int(args[1])
                settings['max_requests'] = max_requests
                settings['window_seconds'] = window_seconds
                save_settings(settings)
                rate_limiter.update_settings(settings['rate_limit_enabled'], max_requests, window_seconds)
                logger.info(f"Rate limit updated: {max_requests} requests per {window_seconds} seconds.")
            except ValueError:
                logger.error('Error: Invalid rate limit parameters.')

    elif command == 'disableratelimit':
        command_executed = True
        settings['rate_limit_enabled'] = False
        save_settings(settings)
        rate_limiter.update_settings(False, rate_limiter.max_requests.value, rate_limiter.window_seconds.value)
        logger.info('Rate limiting has been disabled.')

    elif command == 'enableratelimit':
        command_executed = True
        settings['rate_limit_enabled'] = True
        save_settings(settings)
        rate_limiter.update_settings(True, rate_limiter.max_requests.value, rate_limiter.window_seconds.value)
        logger.info('Rate limiting has been enabled.')

    elif command == 'ratelimitstatus':
        command_executed = True
        status = "enabled" if rate_limiter.enabled.value else "disabled"
        logger.info(f"Rate limiting is currently {status}")
        logger.info(f"Max requests: {rate_limiter.max_requests.value}")
        logger.info(f"Time window: {rate_limiter.window_seconds.value} seconds")

    elif command == 'exit':
        command_executed = True
        os.kill(os.getpid(), signal.SIGTERM)

    if not command_executed:
     logger.error('Unknown command. Available commands: addkey, generatekey, removekey, listkeys, labelkey <key> <label>, removelabel <key>, setratelimit <max_requests> <time_window_in_seconds>, enableratelimit, disableratelimit, ratelimitstatus, exit')

def check_ollama_running(url):
    try:
        result = subprocess.run(['systemctl', 'is-active', 'ollama'], capture_output=True, text=True)
        if result.stdout.strip() == 'active':
            if ddi:
                logging.info("Ollama service is active.")
        else:          
            logging.warning("Ollama service is not active. (this does not matter if your not running ollama on the same server)")
    except subprocess.CalledProcessError:
        logging.warning("Unable to check Ollama service status. This might not be a Linux system or systemctl is not available.")
    except FileNotFoundError:
        logging.warning("systemctl command not found. Unable to check Ollama service status.")

    try:
        response = requests.get(f"{url}/api/tags", timeout=3)
        if response.status_code == 200:
            if ddi:
                logging.info("Ollama server is responding.")
            return True
        else:
            logging.error(f"Ollama server returned unexpected status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        logging.error(f"Failed to connect to Ollama server: {e}")
        return False


atexit.unregister(_exit_function)

class StandaloneApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

def run_cli():
    while True:
        try:
            command_input = input("> ")
            command, *args = command_input.strip().split()
            handle_command(command, args)
        except Exception as e:
            logger.error(f"Error processing command: {e}")

def run_server():
    options = {
        'bind': f'0.0.0.0:{Config.PORT}',
        'workers': 4,
        'worker_class': 'sync',
        'capture_output': True,
        'errorlog': '-',
        'loglevel': 'critical',
        'access_log_format': '%(h)s %(r)s %(s)s %(b)s %(L)s',
        'accesslog': '-',
    }
    StandaloneApplication(app, options).run()

if __name__ == '__main__':

    ollama_url = Config.OLLAMA_SERVER_URL  # Make sure this is defined in your Config class
    if not check_ollama_running(ollama_url):
        logging.error("Ollama is not running or not accessible. Please ensure Ollama is installed or running before trying again.")
        os.kill(os.getpid(), signal.SIGKILL)

    logging.getLogger('gunicorn.error').propagate = False
    load_api_keys()
    load_labels()

    logger.info(f'API server will run on http://0.0.0.0:{Config.PORT}')
    if ddi:
        logger.info(f"Initial rate limit state: {'Enabled' if settings['rate_limit_enabled'] else 'Disabled'}")
    logger.info('Available commands: addkey, generatekey, removekey, listkeys, labelkey <key> <label>, removelabel <key>, setratelimit <max_requests> <time_window_in_seconds>, enableratelimit, disableratelimit, ratelimitstatus, exit')
    
    # Start the CLI in a separate thread
    cli_thread = threading.Thread(target=run_cli)
    cli_thread.daemon = True
    cli_thread.start()

    # Run the server in the main thread
    run_server()
