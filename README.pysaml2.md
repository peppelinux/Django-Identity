pySAML2
-------

````
git clone https://github.com/IdentityPython/pysaml2.git
cd pysaml2
python setup.py install

# unit tests
cd tests
pip install -r test_requirements.txt 

# run tests
py.test

````

### Hints

````
always check idp certificate validity
echo -n | openssl s_client -connect idp.testunical.it:443 | grep Verify

# if local issuer (self signed/private CA)
sudo cp testunical.it_ca.crt /etc/ssl/certs/
sudo update-ca-certificates
echo -n | openssl s_client -connect idp.testunical.it:443 -CAfile /etc/ssl/certs/ca-certificates.crt | grep Verify

# or
echo -n | openssl s_client -connect idp.testunical.it:443 -CAfile /etc/ssl/certs/testunical_ca.crt | grep Verify

````
