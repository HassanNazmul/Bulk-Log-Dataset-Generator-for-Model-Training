NUMBER_OF_LOGS = 250_000

import csv
import random
import datetime
import json
import logging
from faker import Faker

fake = Faker()

# Expanded list of realistic log templates with additional context for realism
real_world_logs = [
    {
        "source": "LinuxKernel",
        "message_template": "Kernel panic at {address}: Fatal exception in {module}",
        "target_label": "Critical Error",
        "severity": "high"
    },
    {
        "source": "ApacheServer",
        "message_template": "AH00126: Invalid URI '{uri}' in request from {client_ip}",
        "target_label": "HTTP Status",
        "severity": "medium"
    },
    {
        "source": "Firewall",
        "message_template": "Blocked unauthorized SSH access attempt from {client_ip}",
        "target_label": "Security Alert",
        "severity": "high"
    },
    {
        "source": "Database",
        "message_template": "MySQL server on {hostname} has gone away",
        "target_label": "Critical Error",
        "severity": "high"
    },
    {
        "source": "AWSLambda",
        "message_template": "Function timeout exceeded in {function_name}",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "WindowsEvent",
        "message_template": "System rebooted without clean shutdown. Error code: {error_code}",
        "target_label": "Critical Error",
        "severity": "high"
    },
    {
        "source": "Cloudflare",
        "message_template": "DDoS attack from {client_ip} mitigated",
        "target_label": "Security Alert",
        "severity": "high"
    },
    {
        "source": "PaymentGateway",
        "message_template": "Transaction failed for user {user_id}: insufficient funds",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "Nginx",
        "message_template": "Unhandled request: {method} {uri} from {client_ip}",
        "target_label": "HTTP Status",
        "severity": "medium"
    },
    {
        "source": "Docker",
        "message_template": "Container {container_id} exited unexpectedly with code {exit_code}",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "Kubernetes",
        "message_template": "Pod {pod_name} evicted due to resource constraints on node {node_name}",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "Splunk",
        "message_template": "Indexer service restarted unexpectedly on host {hostname}",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "Syslog",
        "message_template": "Warning: Excessive open file descriptors detected in process {process}",
        "target_label": "Warning",
        "severity": "low"
    },
    {
        "source": "SSHServer",
        "message_template": "User {user} failed public key authentication from {client_ip}",
        "target_label": "Security Alert",
        "severity": "high"
    },
    {
        "source": "DHCP",
        "message_template": "DHCPDISCOVER from {mac_address} via {interface}",
        "target_label": "System Notification",
        "severity": "low"
    },
    {
        "source": "SoftwareCenter",
        "message_template": "Patch installation failed unexpectedly on system {system}",
        "target_label": "Error",
        "severity": "medium"
    },
    {
        "source": "NetScaler",
        "message_template": "Excessive TCP resets detected on interface {interface}",
        "target_label": "Error",
        "severity": "medium"
    }
]

# Mapping severity to complexity for further processing
severity_map = {
    "high": "llm",
    "medium": "bert",
    "low": "regex"
}

# Additional log levels for realism
log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

def add_complex_details(msg):
    extra_data = {
        "session_id": fake.uuid4(),
        "trace_id": fake.uuid4(),
        "error_code": "E" + str(random.randint(1000, 9999))
    }
    return f"{msg} | extra={json.dumps(extra_data)}"

def generate_real_world_message(template):
    # Replace placeholders in the template with realistic fake data.
    return template.format(
        address=f"0x{random.randint(0x1000, 0xFFFF):X}",
        module=fake.word(),
        uri=fake.uri_path(),
        client_ip=fake.ipv4(),
        hostname=fake.hostname(),
        function_name=fake.word(),
        error_code="E" + str(random.randint(1000, 9999)),
        user_id=fake.user_name(),
        # Added the missing key for {user}
        user=fake.user_name(),
        method=random.choice(["GET", "POST", "PUT", "DELETE"]),
        container_id=fake.md5(raw_output=False)[:12],
        exit_code=random.choice([0, 1, 137, 143]),
        pod_name=f"pod-{fake.word()}-{random.randint(1,100)}",
        node_name=fake.hostname(),
        process=fake.word(),
        mac_address=fake.mac_address(),
        interface=random.choice(["eth0", "wlan0", "ens33"]),
        system=fake.word()
    )

def generate_logs_csv(output_path, num_entries):
    # Additional sources to enrich the synthetic dataset
    sources = [
        "ModernCRM", "AnalyticsEngine", "ModernHR", "BillingSystem", 
        "ThirdPartyAPI", "LegacyCRM", "SupportPortal", "MobileAppInterface", 
        "EventScheduler", "IoTDevice", "EdgeRouter", "LoadBalancer", "CDN",
        "BackupService", "Antivirus", "MobileApp", "WebPortal"
    ]
    
    # Additional synthetic messages with placeholders for dynamic data
    messages = [
        "System reboot initiated by scheduled task",
        "Backup completed successfully for database {db}",
        "Unauthorized access attempt detected from {client_ip}",
        "Critical system error occurred in module {module}",
        "Scheduled maintenance started on server {hostname}",
        "User password changed successfully for {user}",
        "New connection established from {client_ip}",
        "Configuration updated on server {hostname}",
        "Memory leak detected in process {process}",
        "CPU usage exceeded threshold on {hostname}",
        "Network latency detected between {client_ip} and {hostname}",
        "Disk space running low on server {hostname}"
    ]
    
    # Additional target labels to mimic a variety of log categories
    labels = [
        "HTTP Status", "Security Alert", "Error", "Critical Error", 
        "Resource Usage", "User Action", "System Notification", "Workflow Error", 
        "Performance Issue", "Configuration Warning", "Information", "Debug", 
        "Network Issue", "Authentication Failure", "Configuration Error"
    ]
    
    complexities = ["regex", "bert", "llm"]

    with open(output_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Write header including additional fields for realism.
        writer.writerow(["timestamp", "hostname", "process_id", "log_level", "source", "log_message", "target_label", "complexity"])
        
        for _ in range(num_entries):
            # Generate a realistic timestamp using Faker's date_time_between
            ts = fake.date_time_between(start_date="-1y", end_date="now")
            timestamp_str = ts.strftime("%Y-%m-%d %H:%M:%S")
            hostname = fake.hostname()
            process_id = random.randint(100, 9999)
            log_level = random.choices(log_levels, weights=[10, 40, 20, 20, 10])[0]  # INFO is more frequent

            roll = random.random()
            # With roughly a 50% chance, use pre-defined realistic log templates
            if roll < 0.5:
                template_choice = random.choice(real_world_logs)
                source = template_choice["source"]
                msg = generate_real_world_message(template_choice["message_template"])
                label = template_choice["target_label"]
                complexity = severity_map.get(template_choice["severity"], random.choice(complexities))
            else:
                # Generate a synthetic log with additional dynamic placeholders
                source = random.choice(sources)
                template = random.choice(messages)
                msg = template.format(
                    db=fake.word(),
                    client_ip=fake.ipv4(),
                    module=fake.word(),
                    hostname=hostname,
                    user=fake.user_name(),
                    process=fake.word()
                )
                label = random.choice(labels)
                complexity = random.choice(complexities)
            
            # With a 50% chance, add additional complex details to mimic verbose log entries
            if random.random() < 0.5:
                msg = add_complex_details(msg)
            
            writer.writerow([timestamp_str, hostname, process_id, log_level, source, msg, label, complexity])

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("log_generator.log"),
            logging.StreamHandler()
        ]
    )

if __name__ == "__main__":
    setup_logging()
    try:
        logging.info("Starting log generation...")
        if NUMBER_OF_LOGS >= 1_000_000:
            output_file = f"synthetic_logs_{NUMBER_OF_LOGS // 1_000_000}M.csv"
        else:
            output_file = f"synthetic_logs_{NUMBER_OF_LOGS // 1_000}K.csv"
        generate_logs_csv(output_file, NUMBER_OF_LOGS)
        logging.info("Log generation completed successfully.")
    except Exception as e:
        logging.error(f"An error occurred during log generation: {e}")