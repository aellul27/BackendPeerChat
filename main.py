import generate_user_cert
import create_root_certs
import os
import time

if os.path.isfile("./private/ca/rootCAKey.pem") and os.path.isfile("./private/ca/rootCACert.pem"):
    print("Both RootCA key and cert are present.")
else:
    print("Both RootCA key and cert are NOT present.")
    time.sleep(0.5)
    print("\nGenerating now...\n")
    time.sleep(0.5)
    create_root_certs.generate_private_cakey()