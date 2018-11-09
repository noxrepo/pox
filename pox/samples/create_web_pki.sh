#!/bin/bash

# This is a script that demonstrates setting up the POX web server for
# TLS.  Run it and then use the basic_tls_web.cfg configuration file.

# Create stuff for server
# These are for --ssl_server_key and --ssl_server_cert
# This lets you encrypt communication with the server.  Since we're self-
# signing, this doesn't really get you any server authenticity unless you
# verify the fingerprint manually when you overrule your browser's
# objection to the self-signed certificate.
openssl req -newkey rsa:2048 -nodes -keyout server_key.pem -x509 -days 365 \
  -out server_cert.pem -subj "/O=POX Self-Signed"

# Create a user cert so that we can demand that users authenticate themselves
# to the server by providing a cert we trust.  You can provide the resulting
# user_client_cert.pem to --client_certs if you want this.  Otherwise, just
# anyone can connect.  This is sort of like a more secure password.  Of
# course, you could use HTTP authentication instead (or in addition).  As
# of right now, POX only has support for HTTP basic authentication, which
# is horrible, but since the server stuff above means we're encrypting the
# connection, it's not nearly as horrible as usual!
# This also generates a .p12 file, which is imported into the web browser.
# (The browser than sends it to the server, which verifies it using the
# .pem file passed in to --client_certs.)
openssl req -newkey rsa:4096 -keyout user_client_key.pem \
  -out user_client_key_csr.pem -nodes -days 365 \
  -subj "/CN=POX User/O=POX Self-Signed"
openssl x509 -req -in user_client_key_csr.pem -signkey user_client_key.pem \
  -out user_client_cert.pem -days 365
echo
echo "** Enter a password for 'user' when prompted **"
openssl pkcs12 -export -in user_client_cert.pem -inkey user_client_key.pem \
  -out user_client_key.p12

# While we could just pass the above client cert to POX's --client_certs, we
# might want to have multiple *different* clients.  Let's generate another
# client cert the same way.
openssl req -newkey rsa:4096 -keyout user2_client_key.pem \
  -out user2_client_key_csr.pem -nodes -days 365 \
  -subj "/CN=Secondary POX User/O=POX Self-Signed"
openssl x509 -req -in user2_client_key_csr.pem -signkey user2_client_key.pem \
  -out user2_client_cert.pem -days 365
echo
echo "** Enter a password for 'user2' when prompted **"
openssl pkcs12 -export -in user2_client_cert.pem -inkey user2_client_key.pem \
  -out user2_client_key.p12

# Now we can just smash the two client certs together and load the combined
# one into POX via --client_certs.
cat user_client_cert.pem user2_client_cert.pem > all_client_certs.pem

# Show fingerprints
echo "user fingerprint:"
openssl x509 -noout -fingerprint -sha256 -inform pem -in user_client_cert.pem
echo "user2 fingerprint:"
openssl x509 -noout -fingerprint -sha256 -inform pem -in user2_client_cert.pem
echo
echo "Server fingerprint (match this when overriding browser objection):"
openssl x509 -noout -fingerprint -sha256 -inform pem -in server_cert.pem
