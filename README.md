# dso-ip-address-anonymizer
Anonymizes IP addresses in logs or datasets by replacing them with randomly generated, non-routable IP addresses (e.g., from the 192.168.0.0/16 range) or by rounding them to the /24 or /16 prefix, thus preserving network context while removing individual IP traceability. Can handle both IPv4 and IPv6. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-ip-address-anonymizer`

## Usage
`./dso-ip-address-anonymizer [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output file to write the anonymized content. If not provided, output to stdout.
- `-m`: No description provided
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
