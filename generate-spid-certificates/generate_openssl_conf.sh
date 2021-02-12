cat <<EOF
oid_section=spid_oids
[ req ]
default_bits=3072
default_md=sha384
distinguished_name=dn
encrypt_key=no
prompt=no
req_extensions=req_ext
[ spid_oids ]
#organizationIdentifier=2.5.4.97
spid-privatesector-SP=1.3.76.16.4.3.1
spid-publicsector-SP=1.3.76.16.4.2.1
uri=2.5.4.83
[ dn ]
commonName=${COMMON_NAME}
countryName=IT
localityName=${LOCALITY_NAME}
#organizationIdentifier=${ORGANIZATION_IDENTIFIER}
organizationName=${ORGANIZATION_NAME}
serialNumber=${SERIAL_NUMBER}
uri=${URI}
[ req_ext ]
certificatePolicies=@spid_policies
[ spid_policies ]
policyIdentifier=${POLICY_IDENTIFIER}
EOF
