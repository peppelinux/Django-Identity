CERTIFICATES_DIR="`pwd`/djangosaml2_sp/certificates/"
OPENSSL_DOCKER_IMAGE="frapsoft/openssl"

SUBJ_C="IT"
SUBJ_ST="State"
SUBJ_L="City"
SUBJ_O="Acme Inc."
SUBJ_OU="IT Department"
SUBJ_CN="spid-express.selfsigned.example"

set -e

ls $CERTIFICATES_DIR > /dev/null

docker run --rm -v $CERTIFICATES_DIR:/export $OPENSSL_DOCKER_IMAGE req \
  -nodes \
  -new \
  -x509 \
  -sha256 \
  -days 365 \
  -newkey rsa:2048 \
  -subj "/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$SUBJ_CN" \
  -keyout "/export/key.pem" \
  -out "/export/cert.pem"
