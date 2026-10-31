import argparse
import ipaddress
import logging
import os
import random
import re
import sys

from faker import Faker
import chardet

_FAKER = None


def _get_faker():
    global _FAKER
    if _FAKER is None:
        _FAKER = Faker()
    return _FAKER

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Anonymizes IP addresses in a file or string.")
    group = parser.add_mutually_exclusive_group(required=True)  # Either input file or input string required

    group.add_argument("-i", "--input_file", help="Path to the input file containing IP addresses.")
    group.add_argument("-s", "--input_string", help="Input string containing IP addresses.")

    parser.add_argument("-o", "--output_file", help="Path to the output file to write the anonymized content. If not provided, output to stdout.")
    parser.add_argument("-m", "--method", choices=['random', 'prefix24', 'prefix16'], default='random', help="Anonymization method: random (replace with random non-routable IPs; within one run the same original address always receives the same replacement), prefix24 (round to /24), prefix16 (round to /16). Defaults to random.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")

    return parser

def anonymize_ip_address(ip_address_str, method='random'):
    """
    Anonymizes a single IP address string.

    Args:
        ip_address_str (str): The IP address string to anonymize.
        method (str): The anonymization method (random, prefix24, prefix16).

    Returns:
        str: The anonymized IP address string.  Returns original string if IP is invalid.
    """
    try:
        ip_address = ipaddress.ip_address(ip_address_str)

        if method == 'random':
            if isinstance(ip_address, ipaddress.IPv4Address):
                return _get_faker().ipv4_private() # Generate a random private IPv4 address
            elif isinstance(ip_address, ipaddress.IPv6Address):
                 # Draw inside fd00::/8, part of the fc00::/7 unique local range.
                return str(ipaddress.IPv6Address((0xFD << 120) | random.getrandbits(120)))
            else:
                 logging.error(f"Unexpected IP address type: {type(ip_address)}")
                 return ip_address_str

        elif method == 'prefix24':
            if isinstance(ip_address, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip_address_str}/24", strict=False)
                return str(network.network_address)
            elif isinstance(ip_address, ipaddress.IPv6Address):
                network = ipaddress.ip_network(f"{ip_address_str}/112", strict=False)
                return str(network.network_address)  # Use /112 for IPv6 to mimic /24 for IPv4 in terms of granularity
            else:
                logging.error(f"Unexpected IP address type: {type(ip_address)}")
                return ip_address_str

        elif method == 'prefix16':
            if isinstance(ip_address, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip_address_str}/16", strict=False)
                return str(network.network_address)
            elif isinstance(ip_address, ipaddress.IPv6Address):
                network = ipaddress.ip_network(f"{ip_address_str}/104", strict=False)
                return str(network.network_address)  # Use /104 for IPv6 to mimic /16 for IPv4 in terms of granularity
            else:
                logging.error(f"Unexpected IP address type: {type(ip_address)}")
                return ip_address_str
        else:
            logging.error(f"Invalid anonymization method: {method}")
            return ip_address_str

    except ValueError:
        logging.debug(f"Invalid IP address: {ip_address_str}")
        return ip_address_str  # Return the original string if it's not a valid IP

    except Exception as e:
        logging.error(f"An error occurred during IP anonymization: {e}")
        return ip_address_str # Return the original string on error

_IPV4_PATTERN = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
# A candidate is a run of hex digits, colons and dots that either contains a
# colon (an IPv6 form, including one with an embedded dotted IPv4 part such
# as ::ffff:192.0.2.1 or 2001:db8::192.0.2.1) or is a dotted IPv4 address.
# Every candidate is validated with the ipaddress module before anything is
# replaced, so times, version strings and other colon or dot runs that do
# not parse as an address are left alone, and a valid address is always
# anonymized whole, never as a fragment.
_CANDIDATE_PATTERN = re.compile(
    r'(?<![0-9A-Za-z:.])([0-9a-fA-F:.]*:[0-9a-fA-F:.]*|' + _IPV4_PATTERN + r')(?![0-9A-Za-z:])'
)


def anonymize_text(text, method='random'):
    """
    Anonymizes IP addresses within a given text.

    Args:
        text (str): The input text containing IP addresses.
        method (str): The anonymization method to use.

    Returns:
        tuple: The anonymized text and the number of addresses anonymized.
        Within one call, each distinct original address is mapped to one
        replacement and that replacement is reused at every occurrence.
    """
    mapping = {}
    count = 0

    def anonymize_one(ip_text):
        if ip_text not in mapping:
            mapping[ip_text] = anonymize_ip_address(ip_text, method)
        return mapping[ip_text]

    def replace_ip(match):
        nonlocal count
        candidate = match.group(0)
        # 1. The candidate itself is one whole address.
        try:
            ipaddress.ip_address(candidate)
            count += 1
            return anonymize_one(candidate)
        except ValueError:
            pass
        # 2. Trailing punctuation the candidate run picked up (a sentence
        #    ending dot, for example): anonymize the address, keep the rest.
        core = candidate.rstrip('.:')
        if core and core != candidate:
            try:
                ipaddress.ip_address(core)
                count += 1
                return anonymize_one(core) + candidate[len(core):]
            except ValueError:
                pass
        # 3. An address with a trailing :port: anonymize the address part.
        if ':' in candidate:
            head, _, tail = candidate.rpartition(':')
            if head and tail:
                try:
                    ipaddress.ip_address(head)
                    count += 1
                    return anonymize_one(head) + ':' + tail
                except ValueError:
                    pass
        return candidate

    anonymized_text = _CANDIDATE_PATTERN.sub(replace_ip, text)
    return anonymized_text, count


def main():
    """
    Main function to parse arguments, read input, anonymize IP addresses, and write output.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    if args.input_file and args.output_file:
        if os.path.realpath(args.input_file) == os.path.realpath(args.output_file):
            logging.error("Output file is the input file; refusing to overwrite the input. Choose a different output file.")
            sys.exit(1)

    try:
        if args.input_file:
            # Determine encoding of the input file
            with open(args.input_file, 'rb') as f:
                rawdata = f.read()
            result = chardet.detect(rawdata)
            encoding = result['encoding']

            try:
                with open(args.input_file, 'r', encoding=encoding) as infile:
                    text = infile.read()
            except UnicodeDecodeError as e:
                logging.error(f"Error decoding file with encoding {encoding}: {e}")
                sys.exit(1)


        elif args.input_string:
            text = args.input_string
        else:
            logging.error("Either input_file or input_string must be specified.")
            sys.exit(1)

        anonymized_text, anonymized_count = anonymize_text(text, args.method)

        if anonymized_count == 0:
            print("No addresses found in the input; nothing was anonymized.", file=sys.stderr)
            sys.exit(1)

        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as outfile:
                    outfile.write(anonymized_text)
                logging.info(f"Anonymized output written to {args.output_file}")
            except IOError as e:
                 logging.error(f"Error writing to output file: {e}")
                 sys.exit(1)

        else:
            print(anonymized_text)

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()