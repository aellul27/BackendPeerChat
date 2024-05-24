import generate_user_cert

usercsr = generate_user_cert.create_user_csr("test")

user_cert = generate_user_cert.create_user_cert(usercsr)

with open('user_cert.pem', 'wb') as user_cert_file:
    user_cert_file.write(user_cert)