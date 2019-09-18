### djangosaml2-sp (SP server)
````
sudo apt install xmlsec1 mariadb-server libmariadbclient-dev python3-dev python3-pip libssl-dev
pip3 install virtualenv

mkdir djangosaml2_sp
cd djangosaml2_sp

virtualenv -ppython3 djangosaml2_sp.env
source djangosaml2_sp.env/bin/activate

# copy project folder from this git repo
#django-admin startproject djangosaml2_sp

# create your MysqlDB
export USER='djangosaml2_sp'
export PASS='djangosaml2_sp78'
export HOST='%'
export DB='djangosaml2_sp'

sudo mysql -u root -e "\
CREATE USER IF NOT EXISTS '${USER}'@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE IF NOT EXISTS ${DB} CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';\
GRANT ALL PRIVILEGES ON ${DB}.* TO ${USER}@'${HOST}';"

# try the example app here
cd djangosaml2_sp

pip3 install -r requirements
./manage.py migrate

# cd djangosaml2_sp/saml2_sp/saml2_config
# download idp metadata to sp, not needed if remote options is enabled
wget http://idp1.testunical.it:9000/idp/metadata/ -O djangosaml2_sp/saml2_sp/saml2_config/idp_metadata.xml

# cd django_saml2_idp/idp/saml2_config
# download sp metadata to idp [remote not yet working here]
wget http://sp1.testunical.it:8000/saml2/metadata/ -O django_saml2_idp/idp/saml2_config/sp_metadata.xml

./manage.py runserver 0.0.0.0:8000
````
