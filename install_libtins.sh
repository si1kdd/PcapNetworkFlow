#!/usr/bin/env bash

function get_char() {
        saved_stty=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2>/dev/null
        stty -raw
        stty echo
        stty $saved_stty
}

clear
echo " ----------- Install libtins library ------------   "
echo " [*] This scripts would work on FreeBSD and Linux   "
echo "          Just a scripts for lazy guy like me...    "
echo " [!] The default library path is: "
echo "          /usr/local/lib          "
echo "          /usr/local/include      "
echo " [!] You can modify the path by yourself."
echo " ------------------------------------------------   "
echo
echo " [*] Press any key to start... or press Ctrl-C to cancel."
char=`get_char`

echo
echo " [*] Cloning libtins "
git clone https://github.com/mfontanini/libtins.git

echo
echo " [*] Build libtins "

cd libtins && mkdir build && cd build/

# cmake ../ -DCMAKE_INSTALL_PREFIX:PATH=. -DLIBTINS_BUILD_SHARED=1 -DLIBTINS_ENABLE_CXX11=1
cmake ../ -DCMAKE_INSTALL_PREFIX:PATH=/usr/local -DLIBTINS_BUILD_SHARED=1 -DLIBTINS_ENABLE_CXX11=1

make -j4        # suppose 4 Core machine

echo " -------------------------------------------------- "
echo " [!] Now you can use 'make install' to install tins library ...... "
