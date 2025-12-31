import email
from email import policy
import argparse

def parse_eml(file_path):
    with open(file_path, 'r') as f:
        msg = email.message_from_file(f, policy=policy.default)
    headers = dict(msg.items())
    print("Received:", headers.get('Received', 'N/A'))  # Trace path [web:35]
    print("From:", headers.get('From', 'N/A'))
    return headers

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True)
    args = parser.parse_args()
    parse_eml(args.file)
