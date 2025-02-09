# Bulk Log Dataset Generator for Model Training

This project generates a large dataset of synthetic log entries for model training purposes. The logs are generated with realistic templates and additional context to mimic real-world scenarios.

## Features

- Generates up to 250,000 log entries with realistic templates.
- Includes various sources such as LinuxKernel, ApacheServer, Firewall, Database, AWSLambda, WindowsEvent, and more.
- Adds complex details to log messages for enhanced realism.
- Supports different log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL.
- Outputs logs in CSV format with fields: timestamp, hostname, process_id, log_level, source, log_message, target_label, and complexity.

## Requirements

- Python 3.9 and Later
- Faker library

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/HassanNazmul/Bulk-Log-Dataset-Generator-for-Model-Training.git
    cd log-dataset-generator
    ```

2. Install the required dependencies:
    ```sh
    pip install faker
    ```

## Usage

1. Run the log generator script:
    ```sh
    python Log_Generator.py
    ```

2. The generated logs will be saved in a CSV file named `synthetic_logs_250K.csv` by default.

## Configuration

- You can change the number of logs to generate by modifying the `NUMBER_OF_LOGS` variable in the `Log_Generator.py` file.

## Example Log Entry

```
timestamp,hostname,process_id,log_level,source,log_message,target_label,complexity
2024-10-21 04:29:51,desktop-73.gibbs.com,2689,ERROR,ModernHR,User password changed successfully for amanda42,HTTP Status,regex
```

## License

This project is licensed under the MIT License.