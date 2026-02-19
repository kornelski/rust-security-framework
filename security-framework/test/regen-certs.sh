#!/bin/bash
set -xe

cd "$(dirname "$0")"
TEST_DIR="$(pwd)"

openssl genrsa -out ca.key 2048

cat > ca.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = California
L = Palo Alto
O = Foobar LLC
OU = Dev Land
CN = foobar.com

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

# Use 825 days max (Apple's current limit for TLS certificates)
openssl req -new -x509 -key ca.key -out ca.crt -days 825 \
    -sha256 \
    -config ca.cnf

openssl genrsa -out server.key 2048

cat > server_req.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = Palo Alto
O = Foobar LLC
OU = Dev Land
CN = foobar.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = foobar.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key server.key -out server.csr -config server_req.cnf

cat > server_ext.cnf << 'EOF'
[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
subjectAltName = @alt_names

[alt_names]
DNS.1 = foobar.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 825 -sha256 \
    -extfile server_ext.cnf -extensions v3_req

openssl x509 -in ca.crt -out ca.der -outform DER

openssl x509 -in server.crt -out server.der -outform DER

openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt \
    -certfile ca.crt \
    -password pass:password123 \
    -certpbe PBE-SHA1-3DES \
    -keypbe PBE-SHA1-3DES \
    -macalg SHA1 \
    -legacy

rm -f "$TEST_DIR/server.keychain"

security create-keychain -p password123 "$TEST_DIR/server.keychain"

security import server.p12 -k "$TEST_DIR/server.keychain" -P password123 -A

security set-keychain-settings "$TEST_DIR/server.keychain"
security unlock-keychain -p password123 "$TEST_DIR/server.keychain"

rm -f ca.key ca.crt ca.srl server.crt server.csr ca.cnf server_req.cnf server_ext.cnf

######################

cd cms

openssl genrsa -out cms_ca.key 2048

cat > cms_ca.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = CMS Test CA

[v3_ca]
basicConstraints = critical, CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage = critical, keyCertSign, cRLSign
EOF

openssl req -new -x509 -key cms_ca.key -out cms_ca.crt -days 3650 \
    -sha256 -config cms_ca.cnf

openssl genrsa -out cms.key 2048

cat > cms_req.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = cms1
EOF

openssl req -new -key cms.key -out cms.csr -config cms_req.cnf

cat > cms_ext.cnf << 'EOF'
[v3_cms]
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
keyUsage = digitalSignature, keyEncipherment, dataEncipherment, keyAgreement
extendedKeyUsage = emailProtection
EOF

openssl x509 -req -in cms.csr -CA cms_ca.crt -CAkey cms_ca.key -CAcreateserial \
    -out cms.crt -days 3650 -sha256 \
    -extfile cms_ext.cnf -extensions v3_cms

printf 'encrypted message\n' > plaintext.txt

# encrypted.p7m: envelope-encrypted to the CMS cert (no signature)
openssl cms -encrypt -binary -aes-256-cbc \
    -in plaintext.txt -outform DER -out encrypted.p7m \
    cms.crt

# signed.p7m: signed with the CMS key (not encrypted)
openssl cms -sign -binary -nodetach \
    -inkey cms.key -signer cms.crt \
    -in plaintext.txt -outform DER -out signed.p7m

# signed-encrypted.p7m: first sign, then encrypt the signed message
openssl cms -sign -binary -nodetach \
    -inkey cms.key -signer cms.crt \
    -in plaintext.txt -outform DER -out signed_inner.der

openssl cms -encrypt -binary -aes-256-cbc \
    -in signed_inner.der -inform DER -outform DER -out signed-encrypted.p7m \
    cms.crt

openssl pkcs12 -export -out keystore.p12 -inkey cms.key -in cms.crt \
    -password pass:cms \
    -certpbe PBE-SHA1-3DES \
    -keypbe PBE-SHA1-3DES \
    -macalg SHA1 \
    -certfile cms_ca.crt \
    -legacy

rm -f cms_ca.key cms_ca.crt cms_ca.srl cms.key cms.crt cms.csr \
      cms_ca.cnf cms_req.cnf cms_ext.cnf plaintext.txt signed_inner.der
