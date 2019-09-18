### django-saml-idp (IDP server)
````
sudo apt install xmlsec1 mariadb-server libmariadbclient-dev python3-dev python3-pip libssl-dev libmariadb-dev-compat
pip3 install virtualenv

mkdir django-saml2-idp
cd django-saml2-idp

virtualenv -ppython3 django-saml2-idp.env
source django-saml2-idp.env/bin/activate

# copy project folder from this git repo
#django-admin startproject django_saml2_idp

# create your MysqlDB
export USER='django-saml2-idp'
export PASS='django-saml2-idp78'
export HOST='%'
export DB='djangosaml2idp'

# tested on Debian 10
sudo mysql -u root -e "\
CREATE USER IF NOT EXISTS '${USER}'@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE IF NOT EXISTS ${DB} CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';\
GRANT ALL PRIVILEGES ON ${DB}.* TO '${USER}'@'${HOST}';"

# try the example app here
cd django_saml2_idp

pip3 install -r requirements
./manage.py migrate
./manage.py runserver 0.0.0.0:9000
````
