#!bin/bash

function wait() {
	while [ ! -f  $1 ]
	do
		# don't overload the cpu, sleep for sometime, before rechecking the condition
	  sleep 2
	done
}

INTER_IP_ADDR=127.0.0.1
interca=abhi


INTERCA_CERTIFICATE_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/Intermediate.pem
ENCRYPTED_HASH_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/
ENDUSER_CSR_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/
ENDUSER_PUB_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/
ENCRYPTED_HASH_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/encrypted-hash
ENDUSER_CERTIFICATE_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/endUser.pem
INTER_PUB_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/Intermediate.pub
ROOT_CERT_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ENDUSER/root.pem

echo "Generating Private key"
openssl genrsa -aes256 -out endUser.key 2048 -passin pass:cse_iith

echo "Extracting Public key"
openssl rsa -in endUser.key -pubout -out endUser.pub -passin pass:cse_iith

echo "Generating CSR to be signed by the Intermediate CA"
openssl req -new -key endUser.key -out endUser.csr -passin pass:cse_iith

echo "Adding authentication checks to the CSR"

echo "Signing with the private key of endUser/ Sender authentication"
openssl dgst -sha1 -sign endUser.key -passin pass:cse_iith -out sha1.csr.sign endUser.csr

echo "Waiting for the Intermediate CA's certificate"
wait $INTERCA_CERTIFICATE_PATH

echo "Signing with the public key of Intermediate/ Receiver authentication"
openssl smime -encrypt -binary -aes-256-cbc -in sha1.csr.sign -out encrypted-hash -outform DER Intermediate.pem
rm sha1.csr.sign

echo "Sending Encrypted hash for Authenticity and integrity check of CSR at the Intermediate Node"
scp encrypted-hash $interca@$INTER_IP_ADDR:$ENCRYPTED_HASH_PATH_FOR_INTER
rm encrypted-hash

echo "Sending endUser CSR cerificate to Intermediate Node"
scp endUser.csr $interca@$INTER_IP_ADDR:$ENDUSER_CSR_PATH_FOR_INTER

echo "Sending endUser Public key to Intermediate Node/ this is assumed to be available with Intermediate anyway"
scp endUser.pub $interca@$INTER_IP_ADDR:$ENDUSER_PUB_PATH_FOR_INTER

echo "Waiting to receive the hash from the Intermediate Node..."
wait $ENCRYPTED_HASH_PATH
openssl smime -decrypt -binary -in encrypted-hash -inform DER -out sha1-hash -inkey endUser.key -passin pass:cse_iith
echo "RECEIVER authenticity Verified/ I am indeed the intended receiver!!"
rm encrypted-hash

echo "Waiting to receive the Signed cerificate from the Intermediate Node..."
wait $ENDUSER_CERTIFICATE_PATH
echo "Waiting for Intermediate public key"
wait $INTER_PUB_PATH
openssl dgst -sha1 -verify Intermediate.pub -signature sha1-hash endUser.pem
echo "Sender authenticity and Integrity verified!!"
rm sha1-hash

echo "Waiting for Root certificate from Intermediate"
wait $ROOT_CERT_PATH
cat Intermediate.pem root.pem > chain.pem

sudo a2enmod ssl

sudo cp endUser.pem /etc/ssl/certs/endUser.pem
sudo cp endUser.key /etc/ssl/private/enduser.key 
sudo cp chain.pem /etc/ssl/certs/chain.pem

sudo a2ensite default-ssl.conf
sudo service apache2 restart