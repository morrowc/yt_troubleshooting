# YouTube Troubleshooting Script

This Python script is designed to assist with troubleshooting issues related to YouTube. It performs a series of tests to collect data about connectivity and potential problems by leveraging both IPv4 and IPv6 protocols.

## Features

- Tests connectivity to YouTube's redirector using both IPv4 and IPv6.
- Collects and emails results regarding the redirector's mapping and traceroute data.
- Uses `wget` for HTTP requests to retrieve data from specified URLs.
- Provides detailed output for each test, including traceroute results to various destinations.

## Requirements

- Python 3.x
- The following binaries should be available on your system:
  - `traceroute` (or `traceroute6` for IPv6)
  - `wget`
- An SMTP server for sending email results.

## Installation

1. Clone this repository or download the script.
2. Ensure that Python 3.x is installed on your system.
3. Make the script executable:
   ```
   chmod +x yt_troubleshooting.py
   ```

## Usage

To run the script, use the following command:

```
./yt_troubleshooting.py [options]
```

### Options

- `-e`, `--email`: Specify the email address where reports should be sent. Default is `morrowc.lists@gmail.com`.
- `-f`, `--mailfrom`: Specify the email address that the reports should originate from. Default is `morrowc.lists@gmail.com`.
- `-m`, `--mailhost`: Specify the mail host to send email reports through. Default is `mailserver.ops-netman.net`.

### Example

```bash
./yt_troubleshooting.py --email your_email@example.com --mailfrom your_email@example.com --mailhost smtp.example.com
```

## How It Works

1. The script resolves the IPv4 and IPv6 addresses for `redirector.c.youtube.com`.
2. It performs traceroute operations to each of the resolved addresses.
3. It fetches mapping information for both IPv4 and IPv6 from the YouTube redirector.
4. It retrieves the streaming host for video playback.
5. Finally, it compiles the results and sends them via email.

## Error Handling

If there are issues with sending emails, the script will print error messages and exit. Ensure that your SMTP server is correctly configured and reachable.

## Author

- **Email**: morrowc@ops-netman.net

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


### Notes
- Adjust any specifics (like the default email addresses or mail host) to match your preferences or use case.
- Ensure that your SMTP server settings are properly configured to allow sending emails from the script.
- If you need additional sections (like troubleshooting common issues), let me know!
