import argparse
import logging
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    BestAvailableEncryption,
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm, InvalidTag


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Convert between different PEM encoding formats.")

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-i", "--input-file", help="Path to the input PEM file.")
    input_group.add_argument("-p", "--private-key", help="Paste the private key in PEM format.")
    input_group.add_argument("-u", "--public-key", help="Paste the public key in PEM format.")
    input_group.add_argument("-params", "--dhparams", help="Paste the diffie-hellman parameters in PEM format.")

    # Output options
    parser.add_argument("-o", "--output-file", help="Path to the output PEM file (default: stdout).", default=None)
    parser.add_argument("-f", "--output-format",
                        choices=["PKCS1", "PKCS8", "SubjectPublicKeyInfo", "TraditionalOpenSSL"],
                        default="PKCS8",
                        help="Output format (PKCS1, PKCS8, SubjectPublicKeyInfo, TraditionalOpenSSL - default: PKCS8).")

    # Key type option
    parser.add_argument("-t", "--key-type", choices=["private", "public", "dhparams"], default="private",
                        help="Type of key to convert (private, public, dhparams - default: private)")

    # Encryption options
    parser.add_argument("-e", "--encryption", choices=["none", "best"], default="none",
                        help="Encryption to use for private key (none, best - default: none)")
    parser.add_argument("-pw", "--password", help="Password for encrypting private key (required if encryption is 'best').")

    return parser

def convert_pem(input_data, output_file, output_format, key_type, encryption, password):
    """
    Converts the input PEM data to the specified output format.

    Args:
        input_data (str): The PEM-encoded data to convert.
        output_file (str): The path to the output file (or None for stdout).
        output_format (str): The desired output format (PKCS1, PKCS8).
        key_type (str):  The type of key being converted (private, public).
        encryption (str): Encryption method (none, best).
        password (str): Password for encryption (if applicable).
    """
    try:
        if key_type == "private":
            private_key = load_pem_private_key(input_data.encode('utf-8'), password.encode('utf-8') if password else None, backend=default_backend())
            if output_format == "PKCS1":
                output_format_enum = PrivateFormat.PKCS1
            elif output_format == "PKCS8":
                output_format_enum = PrivateFormat.PKCS8
            elif output_format == "TraditionalOpenSSL":
                output_format_enum = PrivateFormat.TraditionalOpenSSL
            else:
                raise ValueError("Invalid output format for private key.")

            if encryption == "none":
                encryption_algorithm = NoEncryption()
            elif encryption == "best":
                if not password:
                    raise ValueError("Password is required for 'best' encryption.")
                encryption_algorithm = BestAvailableEncryption(password.encode('utf-8'))
            else:
                raise ValueError("Invalid encryption option.")

            pem_data = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=output_format_enum,
                encryption_algorithm=encryption_algorithm
            )

        elif key_type == "public":
            public_key = load_pem_public_key(input_data.encode('utf-8'), backend=default_backend())
            if output_format == "SubjectPublicKeyInfo":
                output_format_enum = PublicFormat.SubjectPublicKeyInfo
            else:
                raise ValueError("Invalid output format for public key. Only SubjectPublicKeyInfo is supported.")

            pem_data = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=output_format_enum
            )

        elif key_type == "dhparams":
            dhparams = load_pem_parameters(input_data.encode('utf-8'), backend=default_backend())

            pem_data = dhparams.parameter_bytes(
                encoding=Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )

        else:
            raise ValueError("Invalid key type.")

        if output_file:
            with open(output_file, "wb") as f:
                f.write(pem_data)
            logging.info(f"PEM data written to {output_file}")
        else:
            print(pem_data.decode('utf-8'), end="")

    except FileNotFoundError:
        logging.error(f"Error: Input file not found.")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)
    except InvalidSignature:
        logging.error("Error: Invalid signature. Possible password issue or corrupted file.")
        sys.exit(1)
    except UnsupportedAlgorithm:
         logging.error("Error: Unsupported Algorithm")
         sys.exit(1)
    except InvalidTag:
        logging.error("Error: Invalid Tag")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


def main():
    """
    Main function to execute the PEM format conversion.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    input_data = None
    if args.input_file:
        try:
            with open(args.input_file, "r") as f:
                input_data = f.read()
        except FileNotFoundError:
            logging.error(f"Error: Input file not found: {args.input_file}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading input file: {e}")
            sys.exit(1)
    elif args.private_key:
        input_data = args.private_key
    elif args.public_key:
        input_data = args.public_key
    elif args.dhparams:
        input_data = args.dhparams
    else:
        parser.print_help()  # Show help if no input source is specified.
        sys.exit(1)

    try:
        convert_pem(input_data, args.output_file, args.output_format, args.key_type, args.encryption, args.password)
    except Exception as e:
        logging.error(f"Conversion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Convert a PKCS#1 private key to PKCS#8 (unencrypted):
#    python main.py -i private_key.pem -o private_key_pkcs8.pem -f PKCS8 -t private -e none
#
# 2. Convert a PKCS#1 private key to PKCS#8 (encrypted with a password):
#    python main.py -i private_key.pem -o private_key_pkcs8_encrypted.pem -f PKCS8 -t private -e best -pw "mysecretpassword"
#
# 3. Convert a private key to TraditionalOpenSSL format:
#    python main.py -i private_key.pem -o private_key_traditional.pem -f TraditionalOpenSSL -t private -e none
#
# 4. Convert a public key to SubjectPublicKeyInfo format:
#    python main.py -i public_key.pem -o public_key_spki.pem -f SubjectPublicKeyInfo -t public
#
# 5. Convert Diffie-Hellman Parameters
#    python main.py -i dhparams.pem -o dhparams_out.pem -t dhparams
#
# 6. Convert with private key pasted on the command line:
#   python main.py -p "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" -o private_key_pkcs8.pem -f PKCS8
#
# 7. Convert with public key pasted on the command line:
#   python main.py -u "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" -o public_key_spki.pem -f SubjectPublicKeyInfo -t public
#
# Offensive Tool Usage (Example):
#  - Convert a captured private key to a different format for use with a specific exploit or framework that requires a particular format.
#  - Generate unencrypted private keys from encrypted ones (if the password is known) for use in automated attacks where password prompting is not possible.
#