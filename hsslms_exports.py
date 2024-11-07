import logging
import pickle
from hsslms import HSS_Priv, LMS_ALGORITHM_TYPE, LMOTS_ALGORITHM_TYPE
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def save_to_file(filename, data):
    """Save data to a file using pickle."""
    with open(filename, 'wb') as f:
        pickle.dump(data, f)
    logging.info("Saved data to %s", filename)
    return filename

def load_from_file(filename):
    """Load data from a file using pickle."""
    with open(filename, 'rb') as f:
        data = pickle.load(f)
    logging.info("Loaded data from %s", filename)
    return data

def generate_keys(lms_type_str, lmots_type_str, private_key_file=None, public_key_file=None):
    """Generate and optionally save private and public keys."""
    lms_type = getattr(LMS_ALGORITHM_TYPE, lms_type_str)
    lmots_type = getattr(LMOTS_ALGORITHM_TYPE, lmots_type_str)

    logging.info("LMS Algorithm Type: %s", lms_type)
    logging.info("LMOTS Algorithm Type: %s", lmots_type)

    hss_private_key = HSS_Priv([lms_type]*2, lmots_type)
    logging.debug("Initialized HSS private key with LMS Type: %s and LMOTS Type: %s", lms_type, lmots_type)

    timestamp = datetime.now().strftime('%d%m%Y_%H%M%S')

    if private_key_file:
        private_key_filename = f"{private_key_file}_{timestamp}.priv"
        save_to_file(private_key_filename, hss_private_key)

    hss_public_key = hss_private_key.gen_pub()
    logging.debug("Generated public key: %s", hss_public_key)

    if public_key_file:
        pubilc_key_filename = f"{public_key_file}_{timestamp}.pub"
        publicKey = save_to_file(pubilc_key_filename, hss_public_key)

    return hss_private_key, hss_public_key, publicKey

def sign_message(hss_private_key, message, signature_file=None, save_signed_file=None):
    signature = hss_private_key.sign(message)
    #logging.debug("Generated signature: %s", signature)
    timestamp = datetime.now().strftime('%d%m%Y_%H%M%S')
    
    if signature_file:

        signature_filename = f"{signature_file}_{timestamp}.sign"
        save_to_file(signature_filename, signature)
    if save_signed_file:
        signed_filename = save_signed_file +".signed"
        with open(signed_filename, 'wb') as f:
            f.write(message + b"\n--SIGNATURE--\n"+signature)
        logging.info("Save signed content to %s", signed_filename)  

    return signature

def verify_signature(hss_public_key, message, signature):
    """Verify a message's signature."""
    logging.info("Verifying the message or File ")
    try:
        hss_public_key.verify(message, signature)
        logging.info("Signature verification succeeded.")
        return True
    except Exception as e:
        #logging.error("Error verifying the message or File: %s", e)
        logging.info("Signature verification failed.")
        return False



