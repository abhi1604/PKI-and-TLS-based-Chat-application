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

ROOTCA_CERT_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/
ENCRYPTED_HASH_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/encrypted-hash
INTERMEDIATE_CSR_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/Intermediate.csr
INTERMEDIATE_PUB_PATH=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/ROOT/Intermediate.pub
ENCRYPTED_HASH_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE/
INTER_CERT_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE
ROOT_PUB_PATH_FOR_INTER=/home/abhi/Desktop/Sem8/CNS/PKI-and-TLS-based-Chat-application/Manual/INTERMEDIATE

echo "Generating Private key"
openssl genrsa -aes256 -out root.key 2048 -passin pass:root
echo "Extracting Public key"
openssl rsa -in root.key -pubout -out root.pub -passin pass:root
echo "Self signing the certificate"
openssl req -new -x509 -days 1000 -key root.key -out root.pem -passin pass:root

echo "Sending Root CA's cerificate to Intermediate Node"
scp root.pem $interca@$INTER_IP_ADDR:$ROOTCA_CERT_PATH_FOR_INTER

echo "Waiting for encrypted hash of CSR"
wait $ENCRYPTED_HASH_PATH
openssl smime -decrypt -binary -in encrypted-hash -inform DER -out sha1-hash -inkey root.key -passin pass:root
echo "RECEIVER authenticity Verified/ I am indeed the intended receiver!!"
rm encrypted-hash

echo "Waiting for CSR"
wait $INTERMEDIATE_CSR_PATH
echo "Waiting for Intermediate public key"
wait $INTERMEDIATE_PUB_PATH
openssl dgst -sha1 -verify Intermediate.pub -signature sha1-hash Intermediate.csr
echo "Sender authenticity and Integrity verified!!"
rm sha1-hash

echo "Signing the CSR of Intermediate"
openssl x509 -req -days 1000 -in Intermediate.csr -CA root.pem -CAkey root.key -CAcreateserial -out Intermediate.pem -extfile version.ext -passin pass:root

echo "Adding authentication checks to the Intermediate's signed certificate"

echo "Signing with the private key of Root/ Sender authentication"
openssl dgst -sha1 -sign root.key -passin pass:root -out sha1.pem.sign Intermediate.pem 

echo "Signing with the public key of Intermediate/ Receiver authentication"
openssl smime -encrypt -binary -aes-256-cbc -in sha1.pem.sign -out encrypted-hash -outform DER Intermediate.pem
rm sha1.pem.sign

echo "Sending Encrypted hash for Authenticity and integrity check of signed certificate at the Intermediate Node"
scp encrypted-hash $interca@$INTER_IP_ADDR:$ENCRYPTED_HASH_PATH_FOR_INTER
rm encrypted-hash

echo "Sending signed Intermediate certificate to Intermediate Node"
scp Intermediate.pem $interca@$INTER_IP_ADDR:$INTER_CERT_PATH_FOR_INTER

echo "Sending Root public key to Intermediate Node, this usually happens over email"
scp root.pub $interca@$INTER_IP_ADDR:$ROOT_PUB_PATH_FOR_INTER