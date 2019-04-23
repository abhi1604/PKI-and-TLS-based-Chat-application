#!bin/bash

function wait() {
	while [ ! -f  $1 ]
	do
		# don't overload the cpu, sleep for sometime, before rechecking the condition
	  sleep 2
	done
}

ROOT_IP_ADDR=127.0.0.1
ENDUSER_IP_ADDR=127.0.0.1
endUser=abhi
rootca=abhi

ROOTCA_CERTIFICATE_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/root.pem
INTERMEDIATE_CSR_PATH_FOR_ROOT=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/
INTERMEDIATE_PUB_PATH_FOR_ROOT=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/
ENCRYPTED_HASH_PATH_FOR_ROOT=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/
ENCRYPTED_HASH_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/encrypted-hash
INTER_CA_CERTIFICATE_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/Intermediate.pem
ROOT_PUB_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/root.pub

INTERCA_CERT_PATH_FOR_ENDUSER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/
ENDUSER_CSR_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/endUser.csr
ENDUSER_PUB_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/endUser.pub
ENCRYPTED_HASH_PATH_FOR_ENDUSER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/
ENDUSER_CERT_PATH_FOR_ENDUSER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/
INTERMEDIATE_PUB_PATH_FOR_ENDUSER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/
ROOT_CERT_PATH_FOR_ENDUSER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/

echo "Generating Private key"
openssl genrsa -aes256 -out Intermediate.key 2048 -passin pass:inter
echo "Extracting Public key"
openssl rsa -in Intermediate.key -pubout -out Intermediate.pub -passin pass:inter
echo "Generating CSR to be signed by the Root CA"
openssl req -new -key Intermediate.key -out Intermediate.csr -passin pass:inter

echo "Adding authentication checks to the CSR"

echo "Signing with the private key of Intermediate/ Sender authentication"
openssl dgst -sha1 -sign Intermediate.key -passin pass:inter -out sha1.csr.sign Intermediate.csr 

echo "Waiting for the Root CA's certificate"
wait $ROOTCA_CERTIFICATE_PATH

echo "Signing with the public key of Root/ Receiver authentication"
openssl smime -encrypt -binary -aes-256-cbc -in sha1.csr.sign -out encrypted-hash -outform DER root.pem
rm sha1.csr.sign

echo "Sending Encrypted hash for Authenticity and integrity check of CSR at the Root Node"
scp encrypted-hash $rootca@$ROOT_IP_ADDR:$ENCRYPTED_HASH_PATH_FOR_ROOT
rm encrypted-hash

echo "Sending Intermediate CSR cerificate to ROOT Node"
scp Intermediate.csr $rootca@$ROOT_IP_ADDR:$INTERMEDIATE_CSR_PATH_FOR_ROOT

echo "Sending Intermediate Public key to ROOT Node/ this is assumed to be available with ROOT anyway"
scp Intermediate.pub $rootca@$ROOT_IP_ADDR:$INTERMEDIATE_PUB_PATH_FOR_ROOT

echo "Waiting to receive the hash from the Root Node..."
wait $ENCRYPTED_HASH_PATH
openssl smime -decrypt -binary -in encrypted-hash -inform DER -out sha1-hash -inkey Intermediate.key -passin pass:inter
echo "RECEIVER authenticity Verified/ I am indeed the intended receiver!!"
rm encrypted-hash

echo "Waiting to receive the Signed cerificate from the Root Node..."
wait $INTER_CA_CERTIFICATE_PATH
echo "Waiting for Root public key"
wait $ROOT_PUB_PATH
openssl dgst -sha1 -verify root.pub -signature sha1-hash Intermediate.pem
echo "Sender authenticity and Integrity verified!!"
rm sha1-hash




echo "Sending Intermediate CA's cerificate to endUser Node"
scp Intermediate.pem $endUser@$ENDUSER_IP_ADDR:$INTERCA_CERT_PATH_FOR_ENDUSER


echo "Waiting for encrypted hash of CSR from endUser..."
wait $ENCRYPTED_HASH_PATH
openssl smime -decrypt -binary -in encrypted-hash -inform DER -out sha1-hash -inkey Intermediate.key -passin pass:inter
echo "RECEIVER authenticity Verified/ I am indeed the intended receiver!!"
rm encrypted-hash

echo "Waiting for CSR from endUser..."
wait $ENDUSER_CSR_PATH
echo "Waiting for endUser public key"
wait $ENDUSER_PUB_PATH
openssl dgst -sha1 -verify endUser.pub -signature sha1-hash endUser.csr
echo "Sender authenticity and Integrity verified!!"
rm sha1-hash

echo "Signing the CSR of endUser"
openssl x509 -req -days 1000 -in endUser.csr -CA Intermediate.pem -CAkey Intermediate.key -CAcreateserial -out endUser.pem -extfile version_client.ext -passin pass:inter

echo "Adding authentication checks to the endUser's signed certificate"

echo "Signing with the private key of Intermediate/ Sender authentication"
openssl dgst -sha1 -sign Intermediate.key -passin pass:inter -out sha1.pem.sign endUser.pem

echo "Signing with the public key of endUser/ Receiver authentication"
openssl smime -encrypt -binary -aes-256-cbc -in sha1.pem.sign -out encrypted-hash -outform DER endUser.pem
rm sha1.pem.sign

echo "Sending Encrypted hash for Authenticity and integrity check of signed certificate at the endUser Node"
scp encrypted-hash $endUser@$ENDUSER_IP_ADDR:$ENCRYPTED_HASH_PATH_FOR_ENDUSER
rm encrypted-hash

echo "Sending signed endUser certificate to endUser Node"
scp endUser.pem $endUser@$ENDUSER_IP_ADDR:$ENDUSER_CERT_PATH_FOR_ENDUSER

echo "Sending Intermediate public key to endUser Node, this usually happens over email"
scp endUser.pub $endUser@$ENDUSER_IP_ADDR:$INTERMEDIATE_PUB_PATH_FOR_ENDUSER

echo "Sending Root Certificate to endUser Node, this usually happens over email"
scp root.pem $endUser@$ENDUSER_IP_ADDR:$ROOT_CERT_PATH_FOR_ENDUSER

