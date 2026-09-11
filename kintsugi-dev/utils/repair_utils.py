"""
LLM calls and prompt templates
"""

import os
import re
import json
import logging
from collections import defaultdict
from openai import OpenAI
from utils.whitelist_utils import compute_syscall_diff

logger = logging.getLogger(__name__)


# ==================== LLM Config ====================

# LLM API provider: "deepseek", "openrouter", or "paratera"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek")

# DeepSeek config
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")

# OpenRouter config
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# OpenRouter available models
OPENROUTER_MODELS = {
    "deepseek-v3": "deepseek/deepseek-chat-v3.1",
    "qwen-large": "qwen/qwen3-235b-a22b",
    "qwen-small": "qwen/qwen3-32b",
}

# Active model key: "deepseek-v3", "qwen-large", "qwen-small"
OPENROUTER_MODEL_KEY = os.getenv("OPENROUTER_MODEL_KEY", "deepseek-v3")

OPENROUTER_MODEL = OPENROUTER_MODELS[OPENROUTER_MODEL_KEY]

OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME", "")

# Paratera config
PARATERA_API_KEY = os.getenv("PARATERA_API_KEY", "")
PARATERA_BASE_URL = os.getenv("PARATERA_BASE_URL", "https://llmapi.paratera.com")
PARATERA_MODEL = os.getenv("PARATERA_MODEL", "GLM-5.2")

# Avoid sending huge multipart/file payloads to LLM providers.
LLM_PAYLOAD_CHAR_LIMIT = 6000
LLM_TIMEOUT_SECONDS = 180
LLM_MAX_RETRIES = 1

def create_llm_client() -> OpenAI:
    """
    Create LLM client based on LLM_PROVIDER:
    - "deepseek": DeepSeek API
    - "openrouter": OpenRouter API (100+ models)
    - "paratera": Paratera-compatible OpenAI API
    """
    if LLM_PROVIDER == "openrouter":
        base_url = "https://openrouter.ai/api/v1"

        if OPENROUTER_SITE_URL or OPENROUTER_SITE_NAME:
            headers = {}
            if OPENROUTER_SITE_URL:
                headers["HTTP-Referer"] = OPENROUTER_SITE_URL
            if OPENROUTER_SITE_NAME:
                headers["X-Title"] = OPENROUTER_SITE_NAME

            client = OpenAI(
                api_key=OPENROUTER_API_KEY,
                base_url=base_url,
                default_headers=headers,
                timeout=LLM_TIMEOUT_SECONDS,
                max_retries=LLM_MAX_RETRIES,
            )
        else:
            client = OpenAI(
                api_key=OPENROUTER_API_KEY,
                base_url=base_url,
                timeout=LLM_TIMEOUT_SECONDS,
                max_retries=LLM_MAX_RETRIES,
            )

        logger.info(f"Using OpenRouter API, model: {OPENROUTER_MODEL}")
        return client
    elif LLM_PROVIDER == "paratera":
        logger.info(f"Using Paratera API, model: {PARATERA_MODEL}")
        return OpenAI(
            api_key=PARATERA_API_KEY,
            base_url=PARATERA_BASE_URL,
            timeout=LLM_TIMEOUT_SECONDS,
            max_retries=LLM_MAX_RETRIES,
        )
    else:
        logger.info(f"Using DeepSeek API, model: {DEEPSEEK_MODEL}")
        return OpenAI(
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_BASE_URL,
            timeout=LLM_TIMEOUT_SECONDS,
            max_retries=LLM_MAX_RETRIES,
        )


def call_llm(client: OpenAI, prompt: str, input_text: str, max_tokens: int = 8192) -> str | None:
    """
    Call LLM. Selects model based on LLM_PROVIDER:
    - "deepseek": DEEPSEEK_MODEL
    - "openrouter": OPENROUTER_MODEL
    - "paratera": PARATERA_MODEL
    """
    logger.info("=" * 60)
    logger.info("[PROMPT]")
    logger.info(prompt)
    logger.info("-" * 40)
    logger.info("[INPUT]")
    logger.info(input_text)
    logger.info("=" * 60)

    if LLM_PROVIDER == "openrouter":
        model = OPENROUTER_MODEL
    elif LLM_PROVIDER == "paratera":
        model = PARATERA_MODEL
    else:
        model = DEEPSEEK_MODEL

    try:
        logger.info(f"Calling LLM model={model}, timeout={LLM_TIMEOUT_SECONDS}s, max_retries={LLM_MAX_RETRIES}")
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": input_text},
            ],
            max_tokens=max_tokens,
            stream=False
        )
        result = response.choices[0].message.content

        logger.info("[RESPONSE]")
        logger.info(result)
        logger.info("=" * 60)

        return result
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")

        if hasattr(e, 'response'):
            logger.error(f"HTTP status: {e.response.status_code}")
            logger.error(f"Raw response (first 1000 chars):")
            logger.error(e.response.text[:1000])

        if hasattr(e, 'pos'):
            logger.error(f"JSON error position: {e.pos}")

        import traceback
        logger.error(f"Full traceback:\n{traceback.format_exc()}")


# ==================== Prompt Templates ====================

# Filter mode - $WHITELIST$ placeholder, initially blocks all
PROMPT_REPAIR_FILTER_PHP = """You are a cybersecurity expert. You need to complete a vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but their syscall sequences differ significantly.

You can use tool functions to apply the repair by blocking dangerous syscalls at the kernel level.

[Tool Functions]
1. syscall_filter_begin($WHITELIST$); // start filtering
2. syscall_filter_end($WHITELIST$);   // end filtering

[Important Notes]
- $WHITELIST$ is a placeholder
- The whitelist will be automatically populated in a later stage
- Your primary task is to precisely identify the dangerous code range

[Usage Example]
syscall_filter_begin($WHITELIST$);
// protected code...
syscall_filter_end($WHITELIST$);

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments

[Repair Strategy]
1. Analyze the code to find the specific lines that trigger malicious syscalls
2. Add syscall_filter_begin/end only around the dangerous code segment
3. Keep the filter range as small as possible, wrapping only statements that may execute malicious code

[Output Format]
First provide your analysis, then output the repaired code:
```code
// Complete function code with syscall_filter_begin($WHITELIST$); and syscall_filter_end($WHITELIST$);
```

Requirements:
1. Use $WHITELIST$ as the whitelist placeholder
2. Output must include the complete function definition (signature + body)
3. Filter range must be precise, wrapping only statements that may execute malicious code
4. Only one filter segment is allowed
5. Must output complete code
"""

PROMPT_REPAIR_FILTER_PYTHON = """You are a cybersecurity expert. You need to complete a vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but their syscall sequences differ significantly.

You can use the SyscallFilter context manager to apply the repair by blocking dangerous syscalls at the kernel level.

[Tool Functions]
Import at the beginning of the function:
```python
import sys
if '/tmp/python_syscall_filter' not in sys.path:
    sys.path.insert(0, '/tmp/python_syscall_filter')
from syscall_filter import syscall_filter_begin, syscall_filter_end
```

[Important Notes]
- $WHITELIST$ is a placeholder
- The whitelist will be automatically populated in a later stage
- Your primary task is to precisely identify the dangerous code range

[Usage Example]
syscall_filter_begin($WHITELIST$)
// protected code...
syscall_filter_end($WHITELIST$)

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments

[Repair Strategy]
1. Analyze the code to find the specific lines that trigger malicious syscalls
2. Add syscall_filter_begin/end only around the dangerous code segment
3. Keep the filter range as small as possible

[Output Format]
First provide your analysis, then output the repaired code:
```code
# Complete function code with syscall_filter_begin($WHITELIST$) and syscall_filter_end($WHITELIST$)
```

Requirements:
1. Use $WHITELIST$ as the whitelist placeholder
2. Import statements must be added inside the function
3. Output must include the complete function definition
"""

PROMPT_CHOOSE_METHOD = """You are a cybersecurity expert. You need to determine which repair method should be used for the vulnerability.

[Repair Methods]
1. Syscall whitelist - use eBPF to intercept dangerous process execution/file operations
2. Network filter - use iptables to intercept malicious network requests

[Output Format]
First provide your analysis, then output:
Conclusion: syscall whitelist/network filter
"""

# Direct logic repair - no filter, directly modify code logic
PROMPT_DIRECT_LOGIC_REPAIR_PHP = """You are a cybersecurity expert. You need to complete a vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but their syscall sequences differ significantly.

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments

[Repair Strategy]
1. Carefully analyze the code to find the root cause of the vulnerability
2. Ensure the repair does not affect normal functionality
3. The repair should be concise and efficient, avoiding over-engineering

[Output Format]
First provide your analysis (including vulnerability cause and repair approach), then output the repaired code:
```code
// Complete repaired function code
```

Requirements:
1. Output must include the complete function definition
2. Directly modify the code logic to fundamentally fix the security issue
3. Keep the code concise, making only necessary changes
"""

# Direct localization + repair - LLM directly locates and fixes the vulnerability
PROMPT_DIRECT_LOCALIZATION_REPAIR_PHP = """You are a cybersecurity expert. Below is the code of all functions called during a web request processing.
This request is known to have triggered a security vulnerability.

[Malicious Request Info]
{payload_info}

[Function List]
{function_list}

Follow these steps strictly:

## Step 1: Malicious Request Analysis
Analyze the characteristics of the malicious request and identify the attack type (e.g., SQL injection, command injection, template injection, file inclusion, SSRF, etc.).

## Step 2: Vulnerability Localization
Find the most likely vulnerable function from the function list and analyze the root cause.

## Step 3: Generate Repair Code
Directly fix the vulnerability logic (e.g., add input validation, filter dangerous characters, restrict access scope, etc.).

[Output Format]
First provide detailed analysis, then output the conclusion in the following format:

Vulnerable function: <function name>
Vulnerable file: <full file path>
Repair code:
```php
// Complete repaired function code
```

Requirements:
1. Output must include the complete function definition
2. Directly modify the code logic to fundamentally fix the security issue
3. Keep the code concise, making only necessary changes
4. You may only modify a single function to fix the vulnerability; do not output multiple code blocks
"""

# Localization only - first stage of two-phase mode
PROMPT_DIRECT_LOCALIZATION_ONLY_PHP = """Below is the code of all functions called during a web request processing.
This request is known to have triggered a security vulnerability.

[Malicious Request Info]
{payload_info}

[Function List]
{function_list}

Follow these steps strictly, and output your analysis for each step:

## Step 1: Malicious Request Analysis
Analyze the characteristics of the malicious request and identify the attack type (e.g., SQL injection, command injection, template injection, file inclusion, SSRF, etc.).
Output your analysis here:

## Step 2: Suspicious Function Screening
Based on the attack type, select 3-5 potentially vulnerable functions from the function list and explain why each is suspicious.
Output your analysis here:

## Step 3: Vulnerability Localization
From the suspicious functions, determine the most likely vulnerable function and analyze in detail how it can be exploited by the malicious request.
Output your analysis here:

## Conclusion
Vulnerable function: <function name>
Vulnerable file: <full file path>
Reason: <brief reason, no more than 100 words>
"""

PROMPT_DIRECT_LOCALIZATION_ONLY_PYTHON = """Below is the code of all functions called during a web request processing.
This request is known to have triggered a security vulnerability.

[Malicious Request Info]
{payload_info}

[Function List]
{function_list}

Follow these steps strictly, and output your analysis for each step:

## Step 1: Malicious Request Analysis
Analyze the characteristics of the malicious request and identify the attack type (e.g., SQL injection, command injection, template injection, SSRF, etc.).
Output your analysis here:

## Step 2: Suspicious Function Screening
Based on the attack type, select 3-5 potentially vulnerable functions from the function list and explain why each is suspicious.
Output your analysis here:

## Step 3: Vulnerability Localization
From the suspicious functions, determine the most likely vulnerable function and analyze in detail how it can be exploited by the malicious request.
Output your analysis here:

## Conclusion
Vulnerable function: <function name>
Vulnerable file: <full file path>
Reason: <brief reason, no more than 100 words>
"""

# Single function repair - second stage of two-phase mode
PROMPT_DIRECT_LOGIC_REPAIR_SINGLE_PHP = """You are a cybersecurity expert. You need to repair a vulnerability in an already-identified function.

[Malicious Request Info]
{payload_info}

[Vulnerable Function]
Function: {function_name}
File: {function_path}
Source code:
```php
{source_code}
```

[Repair Requirements]
1. Carefully analyze the code to find the root cause of the vulnerability
2. Directly modify the code logic (e.g., add input validation, filter dangerous characters, restrict access scope, etc.)
3. Ensure the repair does not affect normal functionality
4. The repair should be concise and efficient, avoiding over-engineering

[Output Format]
First provide your analysis (including vulnerability cause and repair approach), then output the repaired code:
```php
// Complete repaired function code
```

Requirements:
1. Output must include the complete function definition
2. Directly modify the code logic to fundamentally fix the security issue
3. Keep the code concise, making only necessary changes
"""

PROMPT_DIRECT_LOGIC_REPAIR_SINGLE_PYTHON = """You are a cybersecurity expert. You need to repair a vulnerability in an already-identified function.

[Malicious Request Info]
{payload_info}

[Vulnerable Function]
Function: {function_name}
File: {function_path}
Source code:
```python
{source_code}
```

[Repair Requirements]
1. Carefully analyze the code to find the root cause of the vulnerability
2. Directly modify the code logic (e.g., add input validation, filter dangerous characters, restrict access scope, etc.)
3. Ensure the repair does not affect normal functionality
4. The repair should be concise and efficient, avoiding over-engineering

[Output Format]
First provide your analysis (including vulnerability cause and repair approach), then output the repaired code:
```python
# Complete repaired function code
```

Requirements:
1. Output must include the complete function definition
2. Directly modify the code logic to fundamentally fix the security issue
3. Keep the code concise, making only necessary changes
"""

PROMPT_DIRECT_LOCALIZATION_REPAIR_PYTHON = """You are a cybersecurity expert. Below is the code of all functions called during a web request processing.
This request is known to have triggered a security vulnerability.

[Malicious Request Info]
{payload_info}

[Function List]
{function_list}

Follow these steps strictly:

## Step 1: Malicious Request Analysis
Analyze the characteristics of the malicious request and identify the attack type (e.g., SQL injection, command injection, template injection, SSRF, etc.).

## Step 2: Vulnerability Localization
Find the most likely vulnerable function from the function list and analyze the root cause.

## Step 3: Generate Repair Code
Directly fix the vulnerability logic (e.g., add input validation, filter dangerous characters, restrict access scope, etc.).

[Output Format]
First provide detailed analysis, then output the conclusion in the following format:

Vulnerable function: <function name>
Vulnerable file: <full file path>
Repair code:
```python
# Complete repaired function code
```

Requirements:
1. Output must include the complete function definition
2. Directly modify the code logic to fundamentally fix the security issue
3. Keep the code concise, making only necessary changes
4. Do not use syscall_filter or net_filter or other external tools
"""

# Network filter mode - for SSRF vulnerability repair
PROMPT_REPAIR_NETWORK_PHP = """You are a cybersecurity expert. You need to complete a network-layer vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but the malicious request triggered anomalous network access.

You can use the NetFilter functions to apply the repair by restricting network access at the network layer.

[Tool Functions]
require_once '/tmp/php_net_filter/net_filter.php';

// Mode 1: Allow external access only, block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
// Use case: Prevent SSRF attacks on internal resources
net_filter_begin(true);   // external_only = true
// ... dangerous network request code ...
net_filter_end();

// Mode 2: Allow internal access only, block external IPs
// Use case: Prevent data exfiltration, reverse shells, etc.
net_filter_begin(false);  // external_only = false (internal_only)
// ... dangerous network request code ...
net_filter_end();

[Important: Handling Asynchronous Code]
The filter tool only supports single-threaded operation. In async scenarios (Promises, callbacks, async tasks, etc.),
you must use closures to wrap the filter inside the function that actually executes the network request.

Example - async callback scenario:
```php
// Wrong (filter is on the main thread, but network request executes in callback)
net_filter_begin(true);
$promise->then(function($result) {
    file_get_contents($url);  // This will NOT be filtered!
});
net_filter_end();

// Correct (place the filter inside the closure)
$promise->then(function($result) {
    require_once '/tmp/php_net_filter/net_filter.php';
    net_filter_begin(true);
    file_get_contents($url);  // Now correctly filtered
    net_filter_end();
});
```

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments

[Repair Strategy]
1. Analyze the syscall diff to determine the attack type:
   - If the malicious request accessed internal IPs -> use net_filter_begin(true) to block internal access
   - If the malicious request accessed external IPs (e.g., reverse shell) -> use net_filter_begin(false) to block external access
2. Find the code that executes user-controllable URL requests (file_get_contents, curl, fopen, etc.)
3. Determine if the code is in an async context (closures, callbacks, Promises, etc.):
   - Synchronous code: wrap directly with net_filter_begin/end
   - Asynchronous code: must place the filter inside the closure/callback
4. Keep the filter range as small as possible, wrapping only statements that may trigger anomalous network access

[Output Format]
First provide your analysis, then output the repaired code:
```code
// Complete function code with require_once '/tmp/php_net_filter/net_filter.php', net_filter_begin() and net_filter_end()
```

Requirements:
1. require_once must be added inside the function (in async scenarios, inside the closure)
2. Output must include the complete function definition (signature + body)
3. Filter range must be precise, wrapping only statements that may trigger anomalous network access
4. Choose the correct mode parameter (true or false) based on the attack type
5. You may only modify the input function; do not fabricate or modify other functions. If the network request is in a called sub-function, wrap the call to that sub-function in the current function
6. [Important] If the network request executes in a closure/callback/async task, the filter must be placed inside that closure
"""

PROMPT_REPAIR_NETWORK_PYTHON = """You are a cybersecurity expert. You need to complete a network-layer vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but the malicious request triggered anomalous network access.

You can use the NetFilter context manager to apply the repair by restricting network access at the network layer.

[Tool Functions]
```python
import sys
sys.path.insert(0, '/tmp/python_net_filter')
from net_filter import NetFilter

# Mode 1: Allow external access only, block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
# Use case: Prevent SSRF attacks on internal resources
with NetFilter(external_only=True):
    response = requests.get(user_url)  # Internal URLs will be blocked

# Mode 2: Allow internal access only, block external IPs
# Use case: Prevent data exfiltration, reverse shells, etc.
with NetFilter(external_only=False):  # internal_only
    response = requests.get(internal_url)  # External URLs will be blocked
```

[Important: Handling Asynchronous Code]
The filter tool only supports single-threaded operation. In async scenarios (async/await, thread pools, callbacks, etc.),
you must use closures to wrap the filter inside the function that actually executes the network request.

Example 1 - async function scenario:
```python
# Wrong (filter is in the outer scope, but the actual network request executes in an async task)
async def fetch_data(url):
    with NetFilter(external_only=True):
        task = asyncio.create_task(do_request(url))
    return await task  # do_request executes after the filter has ended!

# Correct (place the filter inside the actual executing function)
async def fetch_data(url):
    async def do_filtered_request():
        import sys
        sys.path.insert(0, '/tmp/python_net_filter')
        from net_filter import NetFilter
        with NetFilter(external_only=True):
            return await do_request(url)
    return await do_filtered_request()
```

Example 2 - thread pool/executor scenario:
```python
# Wrong
def process(url):
    with NetFilter(external_only=True):
        future = executor.submit(requests.get, url)
    return future.result()  # Request executes in another thread, won't be filtered!

# Correct (define a closure containing the filter)
def process(url):
    def filtered_request():
        import sys
        sys.path.insert(0, '/tmp/python_net_filter')
        from net_filter import NetFilter
        with NetFilter(external_only=True):
            return requests.get(url)
    return executor.submit(filtered_request).result()
```

Example 3 - callback scenario:
```python
# Wrong
def on_complete(url):
    with NetFilter(external_only=True):
        client.fetch(url, callback=handle_response)  # Requests in callback won't be filtered

# Correct
def on_complete(url):
    def filtered_callback(response):
        import sys
        sys.path.insert(0, '/tmp/python_net_filter')
        from net_filter import NetFilter
        with NetFilter(external_only=True):
            process_response(response)
    client.fetch(url, callback=filtered_callback)
```

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments

[Repair Strategy]
1. Analyze the syscall diff to determine the attack type:
   - If the malicious request accessed internal IPs -> use NetFilter(external_only=True) to block internal access
   - If the malicious request accessed external IPs (e.g., reverse shell) -> use NetFilter(external_only=False) to block external access
2. Find the code that executes user-controllable URL requests (requests, urllib, aiohttp, feedparser, etc.)
3. Determine if the code is in an async context (async/await, thread pools, callbacks, etc.):
   - Synchronous code: wrap directly with `with NetFilter()`
   - Asynchronous code: must define a closure containing both the filter and the network request
4. Keep the filter range as small as possible, wrapping only statements that may trigger anomalous network access

[Output Format]
First provide your analysis, then output the repaired code:
```code
# Complete function code
```

Requirements:
1. The following import statements must be added inside the function (all three lines are required):
   import sys
   sys.path.insert(0, '/tmp/python_net_filter')
   from net_filter import NetFilter
   (In async scenarios, add these imports inside the closure)
2. Output must include the complete function definition
3. Filter range must be precise, wrapping only statements that may trigger anomalous network access
4. Choose the correct mode parameter (external_only=True or False) based on the attack type
5. You may only modify the input function; do not fabricate or modify other functions. If the network request is in a called sub-function, wrap the call to that sub-function in the current function
6. [Important] If the network request executes in an async task/thread pool/callback, you must define a closure and place the filter inside it
"""

PROMPT_BATCH_JUDGMENT = """You are a vulnerability repair expert. You are given syscall diff analysis for multiple anomalous functions. Determine which ones require malicious behavior interception.

[Input Format]
Each function includes:
- Function name
- Normal behavior: syscall types, paths, and network connections during normal requests
- Anomalous behavior: extra syscall types, paths, and network connections from malicious requests

[Judgment Criteria]
1. If there are no extra syscall types, paths, or network connections, no repair is needed
2. If suspicious syscalls (e.g., execve, unlink) appear or suspicious paths are accessed, interception is needed
3. If the network access pattern differs (e.g., the malicious request accessed internal IPs while the normal request did not), this may be an SSRF attack and requires interception
4. If the path accesses are normal business operations (e.g., logs, cache) or the network requests follow similar patterns (both accessing internal/external with similar patterns), no repair is typically needed
5. Compare normal and anomalous behavior to determine if the anomalous connections are malicious
6. At least one function must need repair

[Output Format]
```json
{{
  "needs_repair": ["function_name_1", "function_name_2"],
  "no_repair": ["function_name_3", "function_name_4"]
}}
```
"""

# LLM-generated whitelist mode - LLM analyzes syscall data and generates whitelist directly (for ablation study)
PROMPT_REPAIR_FILTER_WITH_WHITELIST_PHP = """You are a cybersecurity expert. You need to complete a vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but their syscall sequences differ significantly.

You can use tool functions to apply the repair by blocking dangerous syscalls at the kernel level.

[Tool Functions]
1. syscall_filter_begin($whitelist); // start filtering, $whitelist is the whitelist array
2. syscall_filter_end($whitelist);   // end filtering

[Whitelist Format]
The whitelist is a PHP array:
```php
[
    'syscall_type1' => ['allowed_path1', 'allowed_path2'],  // only allow these paths
    'syscall_type2' => [],  // empty array means allow any path for this syscall
]
```
syscall_type3 is not in the whitelist, so it will be blocked.

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments
9. [Important] Raw syscall list from normal requests (for whitelist generation)

[Repair Strategy]
1. Analyze the code to find the specific lines that trigger malicious syscalls
2. Add syscall_filter_begin/end only around the dangerous code segment
3. Keep the filter range as small as possible, wrapping only statements that may execute malicious code
4. Analyze the normal request syscall list to generate the whitelist:
   - For syscalls with paths (open, openat, execve), list the paths that should be allowed
5. The whitelist must cover all normal behavior

[Output Format]
First provide your analysis, then output the repaired code:
```code
// Complete function code with syscall_filter_begin($whitelist) and syscall_filter_end($whitelist)
// Write the whitelist directly in the code, do not use placeholders
```

Requirements:
1. Define the whitelist array directly in the code; do not use the $WHITELIST$ placeholder
2. Output must include the complete function definition (signature + body)
3. Filter range must be precise, wrapping only statements that may execute malicious code
4. The whitelist must be generated based on the provided normal request syscall list

Note: **To block a syscall like execve**, do NOT include it in the whitelist (rather than writing it with an empty array). An empty array means allow that syscall with any path.**
"""

PROMPT_REPAIR_FILTER_WITH_WHITELIST_PYTHON = """You are a cybersecurity expert. You need to complete a vulnerability repair task.
You are provided with payloads from both a normal request and a malicious request. Both requests triggered the same function call, but their syscall sequences differ significantly.

You can use the SyscallFilter context manager to apply the repair by blocking dangerous syscalls at the kernel level.

[Tool Functions]
Import at the beginning of the function:
```python
import sys
if '/tmp/python_syscall_filter' not in sys.path:
    sys.path.insert(0, '/tmp/python_syscall_filter')
from syscall_filter import syscall_filter_begin, syscall_filter_end
```

[Whitelist Format]
The whitelist is a Python dictionary:
```python
{{
    'syscall_type': ['allowed_path1', 'allowed_path2'],  # only allow these paths
    'syscall_type': [],  # empty list means allow any path for this syscall
}}
```

[Input Format]
1. Normal request payload
2. Malicious request payload
3. Potentially anomalous function name
4. Function call stack
5. Syscall diff analysis
6. Function source code
7. Normal function call arguments
8. Abnormal function call arguments
9. [Important] Raw syscall list from normal requests (for whitelist generation)

[Repair Strategy]
1. Analyze the code to find the specific lines that trigger malicious syscalls
2. Add syscall_filter_begin/end only around the dangerous code segment
3. Keep the filter range as small as possible
4. Analyze the normal request syscall list to generate the whitelist:
   - The whitelist should include all syscall types from normal requests
   - For syscalls with paths (open, openat, execve, etc.), list the paths that should be allowed
   - If a syscall type has many paths, use directory prefixes (e.g., '/var/log/' instead of specific files)
   - If a syscall type does not need path filtering, use an empty list []

[Output Format]
First provide your analysis, then output the repaired code:
```code
# Complete function code with syscall_filter_begin(whitelist) and syscall_filter_end(whitelist)
# Write the whitelist directly in the code, do not use placeholders
```

Requirements:
1. Define the whitelist dictionary directly in the code; do not use the $WHITELIST$ placeholder
2. Import statements must be added inside the function
3. Output must include the complete function definition
4. The whitelist must be generated based on the provided normal request syscall list
"""

PROMPT_BACKTRACK_REPAIR = """You are a security repair expert analyzing which function is the best place to apply a security fix.

## Currently Detected Anomalous Function
- **Name**: {function_name}
- **Source code**:
```
{source_code}
```

## Call Stack (from entry point to anomalous function)
{call_stack_with_code}

## Malicious Request Payload
{payload}

## Task
Determine the best repair location.

Considerations:
- Generic/utility functions (HTTP clients, file handlers, database queries) should not be modified
- Business logic functions (controllers, validators, handlers) are appropriate repair locations
- The repair location should have access to the exploited user input

## Output (JSON only)
```json
{{
  "should_backtrack": true or false,
  "target_function": "ClassName::methodName or null",
  "target_index": <0-based index in the call stack, or null>,
  "reason": "brief explanation"
}}
```
"""


def get_localization_only_prompt(language: str = "php") -> str:
    """Get localization-only prompt (first stage of two-phase mode)."""
    if language == "python":
        return PROMPT_DIRECT_LOCALIZATION_ONLY_PYTHON
    return PROMPT_DIRECT_LOCALIZATION_ONLY_PHP


def get_single_function_repair_prompt(language: str = "php") -> str:
    """Get single function repair prompt (second stage of two-phase mode)."""
    if language == "python":
        return PROMPT_DIRECT_LOGIC_REPAIR_SINGLE_PYTHON
    return PROMPT_DIRECT_LOGIC_REPAIR_SINGLE_PHP


def get_repair_prompt(language: str = "php", method: str = "syscall", repair_mode: str = "filter", whitelist_mode: str = "static") -> str:
    """
    Get repair prompt.

    Args:
        language: "php" or "python"
        method: "syscall" (syscall whitelist) or "network" (network filter)
        repair_mode: "filter" | "direct" | "direct_localization"
        whitelist_mode: "static" (Stage 9 static analysis) or "llm" (LLM-generated)

    Returns:
        Corresponding prompt string
    """
    if repair_mode == "direct_localization":
        if language == "python":
            return PROMPT_DIRECT_LOCALIZATION_REPAIR_PYTHON
        return PROMPT_DIRECT_LOCALIZATION_REPAIR_PHP

    if repair_mode == "direct":
        if language == "python":
            # TODO: add Python direct logic repair prompt
            return PROMPT_REPAIR_FILTER_PYTHON
        return PROMPT_DIRECT_LOGIC_REPAIR_PHP

    if method == "network":
        if language == "python":
            return PROMPT_REPAIR_NETWORK_PYTHON
        return PROMPT_REPAIR_NETWORK_PHP
    else:
        if whitelist_mode == "llm":
            if language == "python":
                return PROMPT_REPAIR_FILTER_WITH_WHITELIST_PYTHON
            return PROMPT_REPAIR_FILTER_WITH_WHITELIST_PHP
        else:
            if language == "python":
                return PROMPT_REPAIR_FILTER_PYTHON
            return PROMPT_REPAIR_FILTER_PHP


def judge_repair_method(client, pair: dict, return_debug_info: bool = False):
    """
    Call LLM to determine repair method.

    Args:
        client: OpenAI client
        pair: Function pair
        return_debug_info: Whether to return debug info

    Returns:
        If return_debug_info=False: "syscall" or "network"
        If return_debug_info=True: (method, debug_info) tuple
    """
    input_text = format_llm_input(pair)
    response = call_llm(client, PROMPT_CHOOSE_METHOD, input_text, max_tokens=1024)

    if not response:
        logger.warning("LLM repair method judgment failed, defaulting to syscall")
        if return_debug_info:
            return "syscall", {
                'prompt': PROMPT_CHOOSE_METHOD,
                'input': input_text,
                'response': ''
            }
        return "syscall"

    # Extract conclusion
    conclusion = ""
    for line in response.split('\n'):
        line_stripped = line.strip()
        if line_stripped.lower().startswith("conclusion:"):
            conclusion = line_stripped.split(":", 1)[-1].strip()
            break

    method = "syscall"
    if conclusion:
        conclusion_lower = conclusion.lower()
        if "network" in conclusion_lower:
            method = "network"
        else:
            method = "syscall"
    else:
        logger.warning("No 'Conclusion:' marker found, using full-text judgment")
        response_lower = response.lower()
        if "network filter" in response_lower or ("network" in response_lower and "syscall" not in response_lower):
            method = "network"
        else:
            method = "syscall"

    if return_debug_info:
        return method, {
            'prompt': PROMPT_CHOOSE_METHOD,
            'input': input_text,
            'response': response
        }

    return method


# ==================== Input Formatting ====================

def truncate_llm_payload(payload: str, limit: int = LLM_PAYLOAD_CHAR_LIMIT) -> str:
    """Keep request metadata and a suffix while avoiding huge file bodies."""
    if payload is None:
        return "(no data)"
    if len(payload) <= limit:
        return payload

    head_len = limit * 2 // 3
    tail_len = limit - head_len
    return (
        payload[:head_len]
        + f"\n...[payload truncated: original {len(payload)} chars, kept {limit} chars]...\n"
        + payload[-tail_len:]
    )

def format_llm_input(pair: dict, include_raw_syscalls: bool = False) -> str:
    """
    Format LLM input text.

    Args:
        pair: Function pair data
        include_raw_syscalls: Whether to include raw syscall list (for LLM-generated whitelist)
    """
    abnormal = pair['abnormal']
    normal_ref = pair.get('original_normal') or pair.get('normal')

    call_stack = abnormal.get('call_stack', [])
    stack_str = ""
    for i, call in enumerate(call_stack[-20:]):
        stack_str += f"{i+1}. {call['name']} ({call.get('path', 'unknown')}:{call.get('line', 0)})\n"

    diff_str = format_syscall_diff(pair)
    normal_payload = truncate_llm_payload(normal_ref.get('payload') if normal_ref else None)
    malicious_payload = truncate_llm_payload(abnormal.get('payload'))

    input_text = f"""
1. Normal request payload:
{normal_payload}

2. Malicious request payload:
{malicious_payload}

3. Potentially anomalous function name:
{abnormal['function']['name']}

4. Function call stack:
{stack_str}

5. Syscall diff analysis:
{diff_str}

6. Function source code:
{abnormal['function'].get('source_code', '(source code missing)')}

7. Normal function call arguments:
{normal_ref['function']['args'] if normal_ref else '(no data)'}

8. Abnormal function call arguments:
{abnormal['function']['args']}
"""

    if include_raw_syscalls:
        normal_samples = pair.get('normal_samples', [])
        if not normal_samples and normal_ref:
            normal_samples = [normal_ref]

        raw_syscalls_str = format_raw_syscalls(normal_samples)
        input_text += f"""
9. [Important] Raw syscall list from normal requests (for whitelist generation):
{raw_syscalls_str}
"""

    return input_text


def format_raw_syscalls(normal_samples: list) -> str:
    """
    Format raw syscall list from normal samples.

    Args:
        normal_samples: List of normal samples

    Returns:
        Formatted syscall list string with __FCALL__ markers for function call positions
    """
    if not normal_samples:
        return "(no normal sample data)"

    path_fields = ['fd.name', 'evt.arg.path', 'evt.arg.filename']
    lines = []

    for i, sample in enumerate(normal_samples, 1):
        sample_func = sample.get('function', {})
        syscalls = sample_func.get('full_syscalls', sample_func.get('syscalls', []))

        if not syscalls:
            continue

        lines.append(f"--- Sample {i} ---")
        seen = set()

        for sc in syscalls:
            sc_type = sc.get('type')
            if not sc_type:
                continue

            if sc_type == '__FCALL__':
                func_name = sc.get('name', '?')
                func_line = sc.get('line', -1)
                func_path = sc.get('path', '')
                if func_line >= 0:
                    key = f"FCALL:{func_name}:{func_line}"
                    if key not in seen:
                        seen.add(key)
                        lines.append(f"  [Function call] {func_name} @ line {func_line} ({func_path})")
                continue

            path = None
            for field in path_fields:
                if field in sc and sc[field]:
                    path = sc[field]
                    break

            key = f"{sc_type}:{path or ''}"
            if key in seen:
                continue
            seen.add(key)

            if path:
                lines.append(f"  {sc_type}: {path}")
            else:
                lines.append(f"  {sc_type}")

    text = '\n'.join(lines) if lines else "(no syscall data)"
    max_len = 100000
    text = text[:max_len]
    return text

def format_syscall_diff(pair: dict, include_normal: bool = True) -> str:
    """
    Format syscall diff for LLM input.

    Args:
        pair: Function pair data
        include_normal: Whether to include normal behavior info
    """
    abnormal_func = pair['abnormal'].get('function', {})
    abnormal_syscalls = abnormal_func.get('full_syscalls', abnormal_func.get('syscalls', []))
    normal_samples = pair.get('normal_samples', [])

    if not normal_samples:
        normal = pair.get('original_normal') or pair.get('normal')
        if normal:
            normal_samples = [normal]

    diff = compute_syscall_diff(abnormal_syscalls, normal_samples)

    network_syscalls = {'connect', 'sendto', 'sendmmsg', 'recvfrom'}

    result = ""

    if include_normal and normal_samples:
        result += "[Normal behavior baseline]\n"

        normal_types = set()
        normal_paths = defaultdict(set)
        normal_networks = defaultdict(set)
        path_fields = ['fd.name', 'evt.arg.path', 'evt.arg.filename', 'proc.cmdline']

        for sample in normal_samples:
            sample_func = sample.get('function', {})
            syscalls = sample_func.get('full_syscalls', sample_func.get('syscalls', []))
            for sc in syscalls:
                sc_type = sc.get('type')
                if sc_type and sc_type != '__FCALL__':
                    normal_types.add(sc_type)
                    for field in path_fields:
                        if field in sc and sc[field]:
                            if sc_type in network_syscalls:
                                normal_networks[sc_type].add(sc[field])
                            else:
                                normal_paths[sc_type].add(sc[field])

        if normal_types:
            result += f"Syscall types: {', '.join(sorted(normal_types))}\n"
        else:
            result += "Syscall types: (none)\n"

        if normal_networks:
            result += "Network connections:\n"
            for sc_type, addrs in sorted(normal_networks.items()):
                result += f"  - {sc_type}: {', '.join(list(addrs)[:3])}\n"
        else:
            result += "Network connections: (none)\n"

        result += "\n"

    result += "[Anomalous: extra syscall types]\n"
    if diff['type_diff']:
        result += f"{', '.join(sorted(diff['type_diff']))}\n"
    else:
        result += "(none)\n"

    path_diff = {}
    network_diff = {}
    for sc_type, values in diff['path_diff'].items():
        if sc_type in network_syscalls:
            network_diff[sc_type] = values
        else:
            path_diff[sc_type] = values

    result += "\n[Anomalous: extra path accesses]\n"
    if path_diff:
        for sc_type, paths in sorted(path_diff.items()):
            result += f"- {sc_type}: {', '.join(list(paths)[:5])}\n"
    else:
        result += "(none)\n"

    result += "\n[Anomalous: abnormal network connections]\n"
    if network_diff:
        for sc_type, addrs in sorted(network_diff.items()):
            result += f"- {sc_type}: {', '.join(list(addrs)[:5])}\n"
    else:
        result += "(none)\n"

    return result


# ==================== Code Extraction ====================

def extract_code_block(response: str) -> str | None:
    """Extract code block from LLM response (returns the last code block)."""
    if not response:
        return None

    pattern = r'```code\s*(.*?)\s*```'
    matches = re.findall(pattern, response, re.DOTALL)
    if matches:
        return matches[-1].strip()

    pattern = r'```(?:php|python)\s*(.*?)\s*```'
    matches = re.findall(pattern, response, re.DOTALL)
    if matches:
        return matches[-1].strip()

    pattern = r'```\s*(.*?)\s*```'
    matches = re.findall(pattern, response, re.DOTALL)
    if matches:
        return matches[-1].strip()

    logger.warning("No code block found")
    return None


def extract_repair_decision(response: str) -> str | None:
    """Extract repair method decision from LLM response."""
    if not response:
        return None

    response_lower = response.lower()
    if "conclusion: direct repair" in response_lower or "conclusion:direct repair" in response_lower:
        return "direct"
    elif "conclusion: syscall whitelist" in response_lower or "conclusion:syscall whitelist" in response_lower:
        return "filter"

    return None


def parse_json_response(response: str) -> dict:
    """Parse JSON from LLM response."""
    if not response:
        return {}

    try:
        json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = response

        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            fixed_json = re.sub(r'(?<!\\)\\(?!["\\/bfnrtu])', r'\\\\', json_str)
            return json.loads(fixed_json)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON response: {e}")
        return {}


# ==================== Batch Judgment ====================

def batch_judge_repairs(client: OpenAI, pairs: list, return_debug_info: bool = False) -> dict:
    """
    Batch judge which functions need repair.

    Args:
        client: OpenAI client
        pairs: List of function pairs
        return_debug_info: Whether to return debug info (prompt, input, response)

    Returns:
        Dict with needs_repair, no_repair; if return_debug_info=True, also includes _debug field
    """
    if not pairs:
        return {'needs_repair': [], 'no_repair': []}

    input_parts = []
    for i, pair in enumerate(pairs, 1):
        func_name = pair['abnormal']['function']['name']

        diff_str = format_syscall_diff(pair)

        input_parts.append(f"""
=== Function {i}: {func_name} ===
{diff_str}
""")

    input_text = "\n".join(input_parts)

    response = call_llm(client, PROMPT_BATCH_JUDGMENT, input_text)
    result = parse_json_response(response)

    ret = {
        'needs_repair': result.get('needs_repair', []),
        'no_repair': result.get('no_repair', [])
    }

    if return_debug_info:
        ret['_debug'] = {
            'prompt': PROMPT_BATCH_JUDGMENT,
            'input': input_text,
            'response': response
        }

    return ret


# ==================== Backtrack Repair ====================

def determine_repair_location(client: OpenAI, pair: dict, max_levels: int = 3, return_debug_info: bool = False) -> dict:
    """
    Determine repair location, possibly backtracking to an ancestor function.

    Args:
        client: OpenAI client
        pair: Function pair
        max_levels: Maximum backtrack levels
        return_debug_info: Whether to add _backtrack_debug field to the returned pair

    Returns:
        Modified pair (possibly backtracked); if return_debug_info=True, includes _backtrack_debug field
    """
    func_name = pair['abnormal']['function']['name']
    source_code = pair['abnormal']['function'].get('source_code', '(source unavailable)')
    call_stack = pair['abnormal'].get('call_stack', [])
    payload = pair['abnormal'].get('payload', '(none)')

    stack_lines = []
    start_idx = max(0, len(call_stack) - max_levels)
    for i, func in enumerate(call_stack[start_idx:], start=start_idx):
        name = func.get('name', 'unknown')
        path = func.get('path', 'unknown')
        line = func.get('line', 0)
        code = func.get('source_code', '(source unavailable)')

        stack_lines.append(f"[{i}] {name} @ {path}:{line}")
        stack_lines.append(f"```\n{code[:500]}\n```")
        stack_lines.append("")

    call_stack_text = "\n".join(stack_lines)

    prompt = PROMPT_BACKTRACK_REPAIR.format(
        function_name=func_name,
        source_code=source_code[:2000],
        call_stack_with_code=call_stack_text,
        payload=str(payload)[:500]
    )

    response = call_llm(client, prompt, "")
    result = parse_json_response(response)

    debug_info = None
    if return_debug_info:
        debug_info = {
            'prompt': prompt,
            'input': '',
            'response': response
        }

    should_backtrack = result.get('should_backtrack', False)
    target_index = result.get('target_index')

    if not should_backtrack:
        if debug_info:
            pair['_backtrack_debug'] = debug_info
        return pair

    if target_index is None or not (0 <= target_index < len(call_stack)):
        logger.warning(f"Invalid target index {target_index}, keeping original location")
        if debug_info:
            pair['_backtrack_debug'] = debug_info
        return pair

    ancestor = call_stack[target_index]

    if not ancestor.get('source_code'):
        logger.warning(f"Ancestor function {ancestor.get('name')} has no source code, keeping original location")
        if debug_info:
            pair['_backtrack_debug'] = debug_info
        return pair

    logger.info(f"Backtracked to: {ancestor.get('name')} (index {target_index})")

    import copy
    new_pair = copy.deepcopy(pair)
    new_pair['backtracked'] = True
    new_pair['original_function'] = pair['abnormal']['function'].copy()

    new_pair['abnormal']['function'] = {
        'name': ancestor.get('name'),
        'path': ancestor.get('path'),
        'line': ancestor.get('line'),
        'def_path': ancestor.get('def_path'),
        'def_start': ancestor.get('def_start'),
        'def_end': ancestor.get('def_end'),
        'source_code': ancestor.get('source_code'),
        'full_syscalls': ancestor.get('full_syscalls', []),
        'arguments': ancestor.get('arguments'),
    }

    if debug_info:
        new_pair['_backtrack_debug'] = debug_info

    return new_pair
