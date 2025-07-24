import os
from dataclasses import dataclass
from typing import List, Dict, Optional, Union
import json
from dotenv import load_dotenv

# Load environment variables for API keys only
load_dotenv()

@dataclass
class LLMConfig:
    name: str
    type: str  # "ollama" or "openai"
    model: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None

@dataclass
class AnalysisConfig:
    use_call_graph: bool
    selected_behaviors: List[int]  # List of behavior IDs (1-12)
    llm_configs: List[LLMConfig]
    input_type: str  # "androzoo" or "local"
    input_path: str  # Base directory containing APK subfolders
    hash_file: str   # Path to the file containing APK hashes
    output_dir: str
    token_threshold: int = 102400
    max_retries: int = 3
    log_level: str = "INFO"
    smali_subdir: Optional[Union[str, List[str]]] = None  # Can be a single directory or a list of directories
    analysis_approach: str = "progressive"  # "progressive" or "baseline"

# Malicious behavior descriptions
BEHAVIOR_DESCRIPTIONS = {
    1: """Privacy Stealing - Methods that access or exfiltrate sensitive user data including:
(1) - Accessing Contact Lists – Retrieving the user's contact details from the device's storage.
(2) - Reading SMS Messages – Accessing and potentially forwarding SMS messages to external servers.
(3) - Collecting Location Data – Gathering precise GPS or network-based location information.
(4) - Extracting Phone Numbers – Accessing the device's phone number or identifiers such as IMEI and IMSI.
(5) - Harvesting Call Logs – Reading historical data on incoming, outgoing, or missed calls.
(6) - Intercepting Communications – Monitoring or manipulating SMS or call-based communication.
(7) - Exfiltrating User Data – Sending private information to external servers or networks.
Look for: Permission checks, content provider queries, telephony manager access, location services, file operations targeting private directories.""",

    2: """SMS/CALL Abuse - Methods that manipulate SMS and phone call functionality:
(1) - Sending SMS messages without user consent
(2) - Intercepting/blocking incoming SMS (especially 2FA messages)
(3) - Deleting SMS messages (to hide evidence)
(4) - Making calls without user awareness
(5) - Monitoring call logs
Look for: SMS manager operations, broadcast receivers for SMS/calls, telephony API usage, SMS deletion commands.""",

    3: """Remote Control - Methods enabling C&C server communication and remote command execution:
(1) - Network connections to remote servers
(2) - WebSocket protocol usage
(3) - Command parsing and execution
(4) - Dynamic code loading
(5) - Background service creation
Common commands: sendSms, show_fs_float_window (phishing overlays)
Look for: Socket connections, HTTP clients, WebSocket implementations, service registrations, dynamic loading.""",

    4:   """Bank/Financial Stealing - Methods implementing banking trojan functionality:
(1) - Overlay attacks on banking apps
(2) - Credential theft
(3) - Screen capture during banking sessions
(4) - Banking app detection
Example: Exobot-style phishing windows
Look for: Window overlay APIs, package monitoring, screen capture calls, banking app package names in strings.""",

    5: """Ransom - Methods implementing ransomware behavior:
(1) - File encryption operations
(2) - Screen locking mechanisms
(3) - Payment demand displays
(4) - Bitcoin/cryptocurrency payment processing
Example: SLocker patterns
Look for: Encryption APIs, screen locking calls, file system operations, payment-related strings.""",

    6: """Accessibility Abuse - Methods exploiting accessibility services:
(1) - Accessibility service registration
(2) - Screen content monitoring
(3) - Automated UI interaction
(4) - Silent installation attempts
Example: TOASTAMIGO patterns
Look for: Accessibility service declarations, window content observers, automated click events.""",

    7: """Privilege Escalation - Methods attempting to gain elevated privileges:
(1) - Root exploit attempts
(2) - System file modifications
(3) - Admin privilege requests
(4) - Persistent privilege elevation
Examples: LIBSKIN (right_core.apk), ZNIU (Dirty COW)
Look for: Root checking, system file operations, privilege escalation exploits, admin rights requests.""",

    8: """Stealthy Download - Methods for covert app installation:
(1) - Silent app downloads
(2) - Background installation attempts
(3) - Package installer abuse
(4) - ROOT or Accessibility service abuse
Examples: LIBSKIN, TOASTAMIGO patterns
Look for: Download manager usage, package installer calls, hidden installation attempts.""",

    9: """Aggressive Advertising - Methods implementing malicious ad behavior:
(1) - Fake click generation (GhostClicker pattern)
(2) - Forced ad displays
(3) - Background ad loading
(4) - Click fraud implementation
Look for: dispatchTouchEvent abuse, ad library manipulation, screen overlay for ads, click simulation.""",

    10: """Miner - Methods implementing cryptocurrency mining:
(1) - CPU intensive operations
(2) - Cryptocurrency mining code
(3) - Mining pool connections
Examples: HiddenMiner, JSMiner patterns
Look for: High CPU usage patterns, mining library imports, cryptocurrency pool URLs.""",

    11: """Tricky Behavior - Methods implementing evasion techniques:
(1) - Icon/label manipulation
(2) - App hiding mechanisms
(3) - Settings modification
(4) - False uninstall messages
Example: Maikspy error message pattern
Look for: Package visibility changes, settings modifications, fake error messages.""",

    12: """Premium Service Abuse - Methods implementing WAP-Click fraud:
(1) - Automatic premium service subscription
(2) - Hidden browser operations
(3) - WAP-Click abuse
Example: Joker malware pattern
Look for: WAP billing APIs, hidden WebView operations, premium number subscriptions."""
}

def find_apk_path(base_dir: str, apk_hash: str) -> Optional[str]:
    """
    Find the full path of an APK file given its hash by searching all subfolders
    Args:
        base_dir: Base directory to start the search
        apk_hash: Hash of the APK file
    Returns:
        Full path to the APK file if found, None otherwise
    """
    apk_filename = f"{apk_hash}.apk"
    for root, _, files in os.walk(base_dir):
        if apk_filename in files:
            return os.path.join(root, apk_filename)
    return None

def load_apk_hashes(hash_file: str) -> List[str]:
    """
    Load APK hashes from the provided file
    Args:
        hash_file: Path to the file containing APK hashes
    Returns:
        List of APK hashes
    """
    try:
        with open(hash_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Hash file not found: {hash_file}")
        return []
    except Exception as e:
        print(f"Error reading hash file: {str(e)}")
        return []

def load_config(config_path: str = "config.json") -> AnalysisConfig:
    """Load configuration from JSON file and API keys from environment variables"""
    try:
        with open(config_path, 'r') as f:
            config_dict = json.load(f)
        
        # Load API keys from environment variables
        openai_api_key = os.getenv('OPENAI_API_KEY')
        
        # Create LLM configurations
        llm_configs = []
        for llm_config in config_dict.get('llm_configs', []):
            if llm_config['type'] == 'openai' and not openai_api_key:
                print("Warning: OpenAI API key not found in environment variables. Skipping OpenAI configuration.")
                continue
                
            if llm_config['type'] == 'openai':
                llm_config['api_key'] = openai_api_key
                
            llm_configs.append(LLMConfig(**llm_config))
        
        # Validate analysis approach
        analysis_approach = config_dict.get('analysis_approach', 'progressive')
        if analysis_approach not in ['progressive', 'baseline']:
            print(f"Warning: Invalid analysis approach '{analysis_approach}'. Using 'progressive' instead.")
            analysis_approach = 'progressive'
        
        return AnalysisConfig(
            use_call_graph=config_dict.get('use_call_graph', True),
            selected_behaviors=config_dict.get('selected_behaviors', [1, 2, 3, 4]),
            llm_configs=llm_configs,
            input_type=config_dict.get('input_type', 'local'),
            input_path=config_dict.get('input_path', '../../0_Data/APKs'),
            hash_file=config_dict.get('hash_file', '../../0_Data/apk_hashes.txt'),
            output_dir=config_dict.get('output_dir', '../../0_Data/Results'),
            token_threshold=config_dict.get('token_threshold', 102400),
            max_retries=config_dict.get('max_retries', 3),
            log_level=config_dict.get('log_level', 'INFO'),
            smali_subdir=config_dict.get('smali_subdir', None),
            analysis_approach=analysis_approach
        )
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading config file: {str(e)}")
        print("Using default configuration")
        # Use default configuration
        llm_configs = []
        # Add default Ollama config
        llm_configs.append(LLMConfig(
            name="llama",
            type="ollama",
            model="llama2:7b",
            base_url="http://localhost:11434"
        ))
        # Add OpenAI if API key is available
        if openai_api_key:
            llm_configs.append(LLMConfig(
                name="gpt",
                type="openai",
                model="gpt-4",
                api_key=openai_api_key
            ))
        return AnalysisConfig(
            use_call_graph=True,
            selected_behaviors=[1, 2, 3, 4],
            llm_configs=llm_configs,
            input_type="local",
            input_path="../../0_Data/APKs",
            hash_file="../../0_Data/apk_hashes.txt",
            output_dir="../../0_Data/Results",
            token_threshold=102400,
            max_retries=3,
            log_level="INFO",
            smali_subdir=None,
            analysis_approach="progressive"
        )

def validate_config(config: AnalysisConfig) -> bool:
    """Validate the configuration"""
    # Check required API keys
    for llm_config in config.llm_configs:
        if llm_config.type == "openai" and not llm_config.api_key:
            raise ValueError("OpenAI API key is required for OpenAI models. Add it to your .env file.")
        if llm_config.type == "ollama" and not llm_config.base_url:
            raise ValueError("Ollama base URL is required for Ollama models. Update it in config.json.")
    
    # Check Android SDK path
    android_path = os.getenv('ANDROID_PATH')
    if not android_path:
        raise ValueError("ANDROID_PATH is required. Add it to your .env file.")
    
    # Validate paths
    if not os.path.exists(config.input_path):
        raise ValueError(f"Input directory does not exist: {config.input_path}")
    
    if not os.path.exists(config.hash_file):
        raise ValueError(f"Hash file does not exist: {config.hash_file}")
    
    # Create output directory if it doesn't exist
    os.makedirs(config.output_dir, exist_ok=True)
    
    # Validate behaviors
    if not config.selected_behaviors:
        raise ValueError("No behaviors selected for analysis. Update selected_behaviors in config.json.")
    if not all(1 <= b <= 12 for b in config.selected_behaviors):
        raise ValueError("Invalid behavior IDs. Must be between 1 and 12. Update selected_behaviors in config.json.")
    
    return True

def get_behavior_description(behavior_id: int) -> str:
    """Get the description for a specific behavior ID"""
    return BEHAVIOR_DESCRIPTIONS.get(behavior_id, "Unknown behavior")

def get_behavior_name(behavior_id: int) -> str:
    """Get the name for a specific behavior ID"""
    behavior_desc = BEHAVIOR_DESCRIPTIONS.get(behavior_id, "")
    if behavior_desc:
        return behavior_desc.split(":")[0]
    return "Unknown"

def create_output_dirs(config: AnalysisConfig):
    """Create necessary output directories"""
    os.makedirs(config.output_dir, exist_ok=True)
    for behavior_id in config.selected_behaviors:
        behavior_dir = os.path.join(config.output_dir, f"behavior_{behavior_id}")
        os.makedirs(behavior_dir, exist_ok=True)

# # Create a global config instance
# config = load_config()
# validate_config(config) 