export USER='djangosaml2_sp'
export PASS='djangosaml2_sp78'
export HOST='%'
export DB='djangosaml2_sp'

sudo mysql -u root -e "\
CREATE USER ${USER}@'${HOST}' IDENTIFIED BY '${PASS}';\
CREATE DATABASE ${DB} CHARACTER SET utf8 COLLATE utf8_general_ci;\
GRANT ALL PRIVILEGES ON ${DB}.* TO ${USER}@'${HOST}';"
