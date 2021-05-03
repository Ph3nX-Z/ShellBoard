# ShellBoard
Reverse shell generator

![](img/shell.jpg)

## Presentation
ShellBoard is a reverse shell generator and it can be used as a listener for theses. A lot of post-exploitation modules are included in it.

## Usage
### Linux :
```sh
chmod +x install.sh
sudo bash install.sh
ShellBoard
```

## Features

### In the Shell :
```sh
#help          : display help message for inshell commands
#kill          : kill the program and the reverse shell
#exit          : quit the shell and return to command panel
#decal         : skip a request to realign the terminal with the commands
#other:command : use control panel's command in the shell
```

### In the Control Panel :
```sh
shell : invoke shell
exit  : exit the program and the reverse shell
other : display other commands (postexploitation commands)
help  : display help message
```

## Examples

```sh
Shellboard
```

## Contributing

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
