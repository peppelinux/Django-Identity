CERTIFICATES_DIR="`pwd`/../djangosaml2_sp/certificates/"

OPENSSL_DOCKER_IMAGE="frapsoft/openssl"
OPENSSL_CONF="openssl_conf.tmp"
OPENSSL_CMD="docker run --rm -v $CERTIFICATES_DIR:/export/ $OPENSSL_DOCKER_IMAGE"

export COMMON_NAME="SPID example proxy"
export LOCALITY_NAME="Roma"
export ORGANIZATION_IDENTIFIER="1234"
export ORGANIZATION_NAME="SPID example proxy"
export SERIAL_NUMBER="1234567890"
# export POLICY_IDENTIFIER="spid-publicsector-SP"
export POLICY_IDENTIFIER="spid-privatesector-SP"
export URI="https://spid.example.org"
export DAYS="730"

set -e

./generate_openssl_conf.sh > "$CERTIFICATES_DIR/$OPENSSL_CONF"
cp -a oids.conf $CERTIFICATES_DIR

$OPENSSL_CMD req \
  -new \
  -x509 \
  -config /export/$OPENSSL_CONF \
  -days $DAYS \
  -keyout /export/key.pem \
  -out /export/cert.pem \
  -extensions req_ext

# dump (text) the certificate
$OPENSSL_CMD x509 -noout -text -in /export/cert.pem

# dump (ASN.1) the certificate
$OPENSSL_CMD asn1parse \
  -inform PEM \
  -oid /export/oids.conf \
  -i \
  -in /export/cert.pem
