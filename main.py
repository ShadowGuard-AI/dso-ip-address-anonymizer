import argparse
import ipaddress
import logging
import random
import re
import sys

from faker import Faker
import chardet

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
    parser.add_argument("-m", "--method", choices=['random', 'prefix24', 'prefix16'], default='random', help="Anonymization method: random (replace with random non-routable IPs), prefix24 (round to /24), prefix16 (round to /16). Defaults to random.")
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
                fake = Faker()
                return fake.ipv4_private() # Generate a random private IPv4 address
            elif isinstance(ip_address, ipaddress.IPv6Address):
                 # Use a non-routable IPv6 prefix.  Many organizations do not assign private IPv6 addresses in the same way as IPv4.
                return "fd00::" + ":".join([format(random.randint(0, 65535), 'x') for _ in range(7)]) # generate something within fc00::/7 unique local address
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

def anonymize_text(text, method='random'):
    """
    Anonymizes IP addresses within a given text.

    Args:
        text (str): The input text containing IP addresses.
        method (str): The anonymization method to use.

    Returns:
        str: The anonymized text.
    """
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|([0-9a-fA-F:]+:+[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:+)'
    # Match IPv4 and IPv6 addresses

    def replace_ip(match):
        ip_address = match.group(0) # Get the matched IP address
        return anonymize_ip_address(ip_address, method)

    anonymized_text = re.sub(ip_pattern, replace_ip, text)
    return anonymized_text


def main():
    """
    Main function to parse arguments, read input, anonymize IP addresses, and write output.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

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

        anonymized_text = anonymize_text(text, args.method)

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