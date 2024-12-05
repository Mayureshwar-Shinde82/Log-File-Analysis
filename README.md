# Log-File-Analysis

## Overview
This Python script processes server log files to extract and analyze key information. It performs tasks such as counting requests per IP address, identifying the most accessed endpoint, and detecting suspicious activity like potential brute force login attempts.

## Features
#### Requests per IP Address:
Analyzes the log file to count the number of requests made by each IP address.

#### Most Accessed Endpoint:
Identifies the endpoint (e.g., URL or resource path) that was accessed the most times.

#### Suspicious Activity Detection:
Flags IP addresses exceeding a threshold for failed login attempts (default: 10 attempts).

#### Results Export:
Displays results in the terminal and saves them to a CSV file (log_analysis_results.csv) for easy sharing and further analysis.

## Usage
#### 1. Prerequisites
Python 3.x installed on your system.
Log file in the correct format (replace server.log in the script with your file name).
#### 2. Install Dependencies
This script uses the collections and csv libraries, which are part of Python’s standard library. No external dependencies are required.

## Output
Results will be displayed in the terminal.
Results are saved in log_analysis_results.csv.
