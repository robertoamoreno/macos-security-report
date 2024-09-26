# macOS Security and Process Report Tool

## Overview

This tool is designed to perform various security checks and process analyses on macOS systems. It provides a comprehensive report on system integrity, running processes, launchd services, installed applications, network connections, and more.

## Features

- Check running processes
- Analyze launchd services
- List installed applications and identify unsigned apps
- Monitor Homebrew services
- Examine network connections
- Check for recently modified system files
- List cron jobs and scheduled tasks
- Find hidden files and directories
- Verify SSH keys
- Perform basic malware scanning
- Check for outdated software
- Verify system integrity
- Check firewall status
- Identify unauthorized users and groups
- Check disk encryption status
- Monitor network activity with geolocation

## Requirements

- macOS (tested on macOS 14.3.1)
- Python 3.6+
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/macos-security-report.git
   cd macos-security-report
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Download the GeoLite2 City database:
   - Visit https://dev.maxmind.com/geoip/geoip2/geolite2/
   - Download the GeoLite2 City database
   - Place the `GeoLite2-City.mmdb` file in the same directory as the script

## Usage

Run the script with:

```
python3 check.py
```

To use the CLI menu for selecting specific checks:

```
python3 check.py --cli
```

To specify authorized SSH key fingerprints:

```
python3 check.py --authorized-keys "key1,key2,key3"
```

To generate an HTML report:

```
python3 check.py --output html
```

To generate a PDF report:

```
python3 check.py --output pdf
```

## Additional Dependencies

For PDF output, you'll need to install `wkhtmltopdf`:

- On macOS: `brew install wkhtmltopdf`
- On Ubuntu/Debian: `sudo apt-get install wkhtmltopdf`
- On CentOS/RHEL: `sudo yum install wkhtmltopdf`

Make sure to install the additional Python packages:

```
pip install jinja2 pdfkit
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and informational purposes only. Always ensure you have permission to run security scans on the systems you're analyzing.
