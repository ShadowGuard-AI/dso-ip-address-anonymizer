![Banner](banner.png)

# dso-ip-address-anonymizer
Anonymizes IP addresses in logs or datasets by replacing them with randomly generated, non-routable IP addresses (e.g., from the 192.168.0.0/16 range) or by rounding them to the /24 or /16 prefix, thus preserving network context while removing individual IP traceability. Can handle both IPv4 and IPv6. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

How it behaves, in plain terms:

- IPv6 addresses with an embedded dotted IPv4 part (for example `::ffff:192.0.2.1` or `2001:db8::192.0.2.1`) are parsed as one whole address and anonymized whole. No fragment of the original address is left in the output.
- With the random method, one run keeps a single mapping: the same original address receives the same replacement at every occurrence in that run, so repeated visits from one address can still be correlated in the output. A new run draws new replacements.
- Naming the input file as the output file is refused with exit code 1, including through a `./` alias or a symlink. The input is left untouched.
- A run that finds no addresses prints a plain "no addresses found" line, writes no success line, and exits with code 1.

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-ip-address-anonymizer`

## Usage
`./dso-ip-address-anonymizer [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output file to write the anonymized content. If not provided, output to stdout.
- `-m`: Anonymization method: random, prefix24, or prefix16.
- `-v`: Enable verbose logging (DEBUG level).

## License
Copyright (c) ShadowStrikeHQ
