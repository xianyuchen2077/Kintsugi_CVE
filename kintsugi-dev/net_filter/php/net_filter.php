<?php
/**
 * NetFilter - Thread-level Dynamic Network Filtering Based on cgroup + iptables
 *
 * Implement network filtering by adding the current thread to a specific cgroup 
 * with container-side iptables rules:
 * - external_only: Allow external network access only (block internal IPs)
 * - internal_only: Allow internal network access only (block external IPs)
 *
 * Prerequisites:
 * - Host machine has executed setup.sh <container-name>
 * - Container mounts /sys/fs/cgroup:/sys/fs/cgroup:rw
 *
 * Usage:
 *     require_once 'net_filter.php';
 *
 *     net_filter_begin(true);  // external_only=true
 *     $response = file_get_contents($user_url);  // Internal URLs will be blocked
 *     net_filter_end();
 *
 * @version 2.0.0
 */

define('NET_FILTER_CGROUP_BASE', '/sys/fs/cgroup/net_cls');
define('NET_FILTER_CGROUP_EXTERNAL', NET_FILTER_CGROUP_BASE . '/net_filter_external/tasks');
define('NET_FILTER_CGROUP_INTERNAL', NET_FILTER_CGROUP_BASE . '/net_filter_internal/tasks');
define('NET_FILTER_CGROUP_ROOT', NET_FILTER_CGROUP_BASE . '/tasks');

/**
 * Get the system TID of the current thread (Container-side TID, kernel auto-converts to host TID)
 *
 * PHP is single-threaded, so TID = PID, directly use getmypid()
 *
 * @return int Thread ID
 */
function net_filter_get_tid() {
    return getmypid();
}

/**
 * Start network filtering
 *
 * @param bool $external_only true=Allow external network only, false=Allow internal network only
 * @return bool Return true on success
 */
function net_filter_begin($external_only = true) {
    $tid = net_filter_get_tid();
    $cgroup = $external_only ? NET_FILTER_CGROUP_EXTERNAL : NET_FILTER_CGROUP_INTERNAL;

    $result = @file_put_contents($cgroup, (string)$tid);
    if ($result === false) {
        trigger_error("net_filter: Failed to write to cgroup ($cgroup)", E_USER_WARNING);
        return false;
    }
    return true;
}

/**
 * Stop network filtering and restore normal network access
 *
 * @return bool Return true on success
 */
function net_filter_end() {
    $tid = net_filter_get_tid();

    $result = @file_put_contents(NET_FILTER_CGROUP_ROOT, (string)$tid);
    if ($result === false) {
        trigger_error("net_filter: Failed to write to root cgroup", E_USER_WARNING);
        return false;
    }
    return true;
}

/**
 * NetFilter Class - Object-Oriented Interface
 *
 * Usage:
 *     $filter = new NetFilter(true);  // external_only mode
 *     $filter->begin();
 *     // ... Network operations ...
 *     $filter->end();
 */
class NetFilter {
    private $external_only;
    private $active = false;

    /**
     * @param bool $external_only true=Allow external network only, false=Allow internal network only
     */
    public function __construct($external_only = true) {
        $this->external_only = $external_only;
    }

    /**
     * Start network filtering
     */
    public function begin() {
        if (!$this->active) {
            net_filter_begin($this->external_only);
            $this->active = true;
        }
        return $this;
    }

    /**
     * Stop network filtering
     */
    public function end() {
        if ($this->active) {
            net_filter_end();
            $this->active = false;
        }
        return $this;
    }

    /**
     * Automatically stop filtering on destruct
     */
    public function __destruct() {
        $this->end();
    }
}