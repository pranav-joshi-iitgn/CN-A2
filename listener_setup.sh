sudo mkdir /etc/systemd/resolved.conf.d/
sudo echo "DNSStubListenerExtra=10.0.0.6" >> /etc/systemd/resolved.conf.d/additional-listening-interfaces.conf
