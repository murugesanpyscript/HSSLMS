import argparse
from hsslms_exports import generate_keys, sign_message, verify_signature, load_from_file


def main(args):
    if args.generate:
        hss_private_key, hss_public_key, publicKey= generate_keys(
            args.lms_type, args.lmots_type,
            args.save_private_key, args.save_public_key
        )

    if args.sign:
        hss_private_key = load_from_file(f"{args.private_key_file}.priv")
        if args.message:
            message = args.message.encode('utf-8')
            #hss_private_key = load_from_file(f"{args.private_key_file}.priv")
            sign_message(hss_private_key, message, args.save_signature)
        elif args.file:
            with open(args.file,'rb') as f:
                file_content = f.read()
            sign_message(hss_private_key, file_content, args.save_signature, args.file)


    if args.verify:
        hss_public_key = load_from_file(f"{args.public_key_file}.pub")
        signature = load_from_file(f"{args.signature_file}.sign")

        if args.message:
            message = args.message.encode('utf-8')
            verify_signature(hss_public_key, message, signature)
        elif args.file:
            with open(args.file,'rb') as f:
                file_content = f.read()
            verify_signature(hss_public_key, file_content, signature)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HSSLMS Cryptographic Operations")
    
    # General arguments
    parser.add_argument('--message', type=str, help='Message to sign/verify')
    parser.add_argument('--file', type=str, help='File to sign/verify')
    
    # Arguments for key generation and signing
    parser.add_argument('--generate', action='store_true', help='Generate keys')
    parser.add_argument('--lms_type', type=str, help='LMS Algorithm Type (e.g., LMS_SHA256_M24_H15)')
    parser.add_argument('--lmots_type', type=str, help='LMOTS Algorithm Type (e.g., LMOTS_SHA256_N24_W4)')
    parser.add_argument('--save_private_key', type=str, help='File prefix to save the private key as .priv')
    parser.add_argument('--save_public_key', type=str, help='File prefix to save the public key as .pub')

    # Arguments for signing
    parser.add_argument('--sign', action='store_true', help='Signature the message or file')
    parser.add_argument('--save_signature', type=str, help='File prefix to save the signature as .sign')
    
    # Arguments for verification
    parser.add_argument('--verify', action='store_true', help='Verify an existing signature')
    parser.add_argument('--public_key_file', type=str, help='File prefix for the public key to load for verification (without .pub extension)')
    parser.add_argument('--private_key_file', type=str, help='File prefix for the private key to load for verification (without .priv extension)')
    parser.add_argument('--signature_file', type=str, help='File prefix for the signature to load for verification (without .sign extension)')





    args = parser.parse_args()

    if args.generate:
        if not all([args.lms_type, args.lmots_type, args.save_private_key, args.save_public_key]):
            parser.error("--generate requires --lms_type, --lmots_type, --save_private_key, --save_public_key")
    if args.sign:
        if not all([args.private_key_file, args.save_signature]):
            parser.error("--sing requires --private_key_file, --save_signature, --message or --file.")
    if args.verify:
        if not all([args.public_key_file, args.signature_file]):
            parser.error("--verify requires --public_key_file, --signature_file and --message or --file.")

    
    main(args)
