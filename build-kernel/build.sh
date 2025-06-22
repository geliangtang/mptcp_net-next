make C=.. O=. menuconfig
make C=.. O=. -j`nproc`
version=$(sudo make C=.. O=. INSTALL_MOD_STRIP=1 modules_install | tee /dev/tty | tail -n 1 | cut -d '/' -f 4)
echo "copy /boot/vmlinuz-$version"
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-$version
echo "copy /boot/config-$version"
sudo cp .config /boot/config-$version
echo "make /boot/initrd.img-$version"
sudo mkinitramfs -o /boot/initrd.img-$version $version
sudo update-grub
