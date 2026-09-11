# NetFilter
Thread-level dynamic network interception based on cgroup + iptables, used to prevent SSRF attacks.

## Working Principle
```
┌─────────────────────────────────────────────────────────┐
│  Application Code                                        │
│  with NetFilter(external_only=True):                    │
│      requests.get(url)  # Internal network blocked       │
└──────────────────┬──────────────────────────────────────┘
                   │ Write TID to cgroup
                   ▼
┌─────────────────────────────────────────────────────────┐
│  cgroup (net_cls)                                       │
│  /sys/fs/cgroup/net_cls/net_filter_external/tasks       │
│  classid = 0x100001                                     │
└──────────────────┬──────────────────────────────────────┘
                   │ iptables matches classid
                   ▼
┌─────────────────────────────────────────────────────────┐
│  iptables                                               │
│  -m cgroup --cgroup 0x100001 -d 10.0.0.0/8 -j DROP     │
│  -m cgroup --cgroup 0x100001 -d 172.16.0.0/12 -j DROP  │
│  -m cgroup --cgroup 0x100001 -d 192.168.0.0/16 -j DROP │
└─────────────────────────────────────────────────────────┘
```

## Installation
### 1. Host Setup (One-time)
```bash
cd net_filter
sudo ./setup.sh
```

### 2. Docker Container Configuration
Add the cgroup mount in `docker-compose.yml`:
```yaml
services:
  web:
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
```

### 3. Copy Language-Specific Module to Container
```bash
# Python
docker cp python/net_filter.py container_name:/app/

# PHP
docker cp php/net_filter.php container_name:/var/www/html/
```

## Usage
### Python
```python
from net_filter import NetFilter

# Prevent SSRF attacks targeting internal network
with NetFilter(external_only=True):
    response = requests.get(user_provided_url)
    # If the URL points to internal network (10.x, 172.16.x, 192.168.x, 127.x)
    # The connection will be dropped by iptables (timeout)

# Restrict access to internal network only
with NetFilter(internal_only=True):
    response = requests.get("http://internal-api/data")
    # External requests will be blocked
```

### PHP
```php
require_once 'net_filter.php';

// Functional API
net_filter_begin(true);  // external_only=true
$response = file_get_contents($user_url);
net_filter_end();

// Object-Oriented API
$filter = new NetFilter(true);  // external_only
$filter->begin();
$response = file_get_contents($user_url);
$filter->end();
```

## Filter Modes
| Mode | Description | Blocked IP Ranges |
|------|-------------|-------------------|
| `external_only=True` | External network only | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
| `internal_only=True` | Internal network only | All non-internal IPs |

## Application Scenarios
### CVE-2024-25737 SSRF Fix
```php
// VuFind CoverController.php
require_once 'net_filter.php';

public function showAction() {
    $url = $this->params()->fromQuery('proxy');
    if (!empty($url)) {
        net_filter_begin(true);  // External network only
        try {
            $image = $this->proxy->fetch($url);
            // Internal URLs will be blocked
        } finally {
            net_filter_end();
        }
    }
}
```