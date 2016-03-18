#!/usr/bin/env bash

echo "#########################################"
echo "#      Carteiro Installation Script     #"
echo "#      Author Tobias Löb                #"
echo "#########################################"
echo
echo "******** Installing Dependencys *********"
echo 
#Update
sudo apt-get update
#Install dependecies Distribution
sudo apt-get install -q -y python3.5 libpython3.5-dev python3-dateutil python3-django python3-isodate python3-xmltodict python3-ecdsa python3-paramiko python3-psycopg2
#Install Apache2 WebServer silently
sudo apt-get install -q -y apache2 libapache2-mod-wsgi-py3
#Install Postgres DB
sudo apt-get -q -y install postgresql
#Install Dependencys Non-Distribution
sudo apt-get -q -y install python3-pip
sudo pip3 install asyncio semanticui-forms
echo
echo "******** Copy Files *********"
echo
#Copy Carteiro Files
sudo mkdir /var/www/carteiro.web/
sudo \cp -r -f -v /vagrant/static/carteirofiles/carteiro/Carteiro/* /var/www/carteiro.web/
#Copy Site Configuratione
sudo \cp -f -v /vagrant/static/carteirofiles/carteiro_web.conf /etc/apache2/sites-available
#Copy Stable WinRM Version
sudo \cp -r -f -v /vagrant/static/carteirofiles/winrm/* /usr/lib/python3/dist-packages/
echo
echo "******** Setting Up the Database *********"
echo
#Setting up the Database
CUSER="$(python3 /vagrant/static/carteirofiles/carteiro/Carteiro/carteiro_settings.py db_user)"
CPASSWD="$(python3 /vagrant/static/carteirofiles/carteiro/Carteiro/carteiro_settings.py db_user)"
echo "USERNAME: $CUSER"
echo "PASSWORD: $CPASSWD"
sudo -u postgres createuser "$CUSER" 
sudo -u postgres createdb -O "$CUSER" carteiro_data
sudo -u postgres psql -d carteiro_data -c "ALTER USER "$CUSER" WITH PASSWORD '$CPASSWD'"
python3 /var/www/carteiro.web/manage.py syncdb --noinput
echo
echo "******** Enable Website *********"
echo
#EnableSite
sudo a2dissite 000-default.conf
sudo a2ensite carteiro_web.conf
sudo /etc/init.d/apache2 reload
echo
echo "******** Inserting Firewall Rule *********"
echo
# Firewall Settings for Apache Web
sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
