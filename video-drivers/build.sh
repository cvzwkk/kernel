# Baixar o código do GCC 14 (ou versão atual)
wget https://gnu.org
tar -xf gcc-14.1.0.tar.gz
cd gcc-14.1.0

# Baixar os pré-requisitos internos (mpfr, gmp, mpc)
./contrib/download_prerequisites

# Configurar e compilar (pode levar horas)
mkdir build && cd build
../configure --prefix=/usr/local --enable-languages=c,c++ --disable-multilib
make -j$(nproc)
sudo make install
cd ../..

wget https://www.kernel.org/pub/software/scm/git/git-2.51.0.tar.gz
tar -xzf git-2.51.0.tar.gz
cd git-2.51.0

make configure
./configure --prefix=/usr/local
make -j"$(nproc)"
sudo make install

git clone https://github.com
cd CMake
./bootstrap --prefix=/usr/local
make -j$(nproc)
sudo make install
cd ..

# Headers
git clone https://github.com
cd Vulkan-Headers
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --target install
cd ..

# Loader (Biblioteca dinâmica libvulkan.so)
git clone https://github.com
cd Vulkan-Loader
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DVULKAN_HEADERS_INSTALL_DIR=/usr/local
cmake --build build --config Release -j$(nproc)
sudo cmake --install build
cd ..

git clone https://github.com
cd Vulkan-Tools
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --config Release -j$(nproc)
sudo cmake --install build
cd ..

git clone https://freedesktop.org
cd mesa

# Configurar o build ativando especificamente o driver Vulkan da AMD (radv)
# Nota: Remova o driver 'swrast' se não quiser o driver de fallback por software
meson setup build/ \
  --prefix=/usr/local \
  -Dbuildtype=release \
  -Dgallium-drivers=radeonsi \
  -Dvulkan-drivers=amd \
  -Dplatforms=x11,wayland

# Compilar e instalar
ninja -C build/ -j$(nproc)
sudo ninja -C build/ install
cd ..   
