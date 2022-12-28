
sudo apt-get update
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config

git clone https://github.com/OISF/suricata.git
cd suricata

git clone https://github.com/ironbee/libhtp
cd libhtp
libtoolize --automake --copy
aclocal -I .
autoheader
automake --add-missing --copy
autoconf
./configure
make
sudo make install
sudo ldconfig
cd ..

libtoolize --automake --copy
aclocal -I .
autoheader
automake --add-missing --copy
autoconf

./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
sudo ldconfig
sudo make install-full
cd ..

