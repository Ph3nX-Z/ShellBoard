apt install python3
apt install python3-pip
pip3 install netifaces
pip3 install pyperclip
pip install pyinstaller
pyinstaller --onefile ./ShellBoard.py
cp ./dist/ShellBoard /bin/ShellBoard
echo "[*] Installed ShellBoard"
echo "[+] Installation Complete !"
