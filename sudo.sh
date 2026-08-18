# Option A: Clone via Git
git clone https://github.com/sudo-project/sudo.git
cd sudo

# Option B: Download and extract a stable release tarball (replace version accordingly)
# wget https://www.sudo.ws/dist/sudo-1.9.15.tar.gz
# tar -zxvf sudo-1.9.15.tar.gz
# cd sudo-1.9.15

./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
sudo -V
