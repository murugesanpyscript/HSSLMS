# HSSLMS
python lmssign.py --generate --lms_type LMS_SHA256_M24_H15 --lmots_type LMOTS_SHA256_N24_W4 --save_private_key "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\privateKey" --save_public_key "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\PublicKey" 

python lmssign.py --sign --private_key_file  "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\privateKey_03092024_224432" --save_signature "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\signatureFile" --message "Welcome to Solidigm Technology"


python lmssign.py --verify --public_key_file "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\PublicKey_03092024_224432" --signature_file "C:\Users\mmadappa\OneDrive - NANDPS\Python\LMS\HSSLMS Code\keyFile\signatureFile_03092024_224549" --message "Welcome to Solidigm Technology"

