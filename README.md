# vultr-cli

The Vultr Command Line Interface

```
vultr-cli is a command line interface for the Vultr API

Usage:
  vultr-cli [command]

Available Commands:
  account            Commands related to account information
  apps               Display applications
  backups            Display backups
  bare-metal         Commands to manage bare metal servers
  billing            Display billing information
  block-storage      Commands to manage block storage
  cdn                Commands to manage your CDN zones
  completion         Generate the autocompletion script for the specified shell
  container-registry Commands to interact with container registries
  database           Commands to manage databases
  dns                Commands to control DNS records
  firewall           Commands to manage firewalls
  help               Help about any command
  inference          Commands to manage serverless inference
  instance           Commands to interact with instances
  iso                Commands to manage ISOs
  kubernetes         Commands to manage kubernetes clusters
  load-balancer      Commands to managed load balancers
  marketplace        Display marketplace information
  object-storage     Commands to manage object storage
  os                 Display available operating systems
  plans              Display available plan information
  regions            Display regions information
  reserved-ip        Commands to interact with reserved IPs
  script             Commands to interact with startup scripts
  snapshot           Commands to interact with snapshots
  ssh-key            Commands to manage SSH keys
  user               Commands to manage users
  version            Display the vultr-cli version
  vpc                Commands to manage VPCs

Flags:
      --config string   config file (default is $HOME/.vultr-cli.yaml)
  -h, --help            help for vultr-cli
  -o, --output string   output format [ text | json | yaml ] (default "text")

Use "vultr-cli [command] --help" for more information about a command.
```

## Installation

These are the options available to install `vultr-cli`:
1. Download a release from GitHub
2. From source
3. Package Manager
  - Arch Linux
  - Brew
  - OpenBSD (-current)
  - Snap (Coming soon)
  - Chocolatey
4. Docker

### GitHub Release
If you are to visit the `vultr-cli` [releases](https://github.com/vultr/vultr-cli/releases) page. You can download a compiled version of `vultr-cli` for you Linux/MacOS/Windows in 64bit.

### Building from source

You will need Go installed on your machine in order to work with the source (and make if you decide to pull the repo down).

`go install github.com/vultr/vultr-cli/v3@latest`

Another way to build from source is to

```sh
git clone git@github.com:vultr/vultr-cli.git or git clone https://github.com/vultr/vultr-cli.git
cd vultr-cli
make builds/vultr-cli_(pass name of os + arch, as shown below)
```

The available make build options are
- make builds/vultr-cli_darwin_amd64
- make builds/vultr-cli_darwin_arm64
- make builds/vultr-cli_linux_386
- make builds/vultr-cli_linux_amd64
- make builds/vultr-cli_linux_arm64
- make builds/vultr-cli_windows_386.exe
- make builds/vultr-cli_windows_amd64.exe
- make builds/vultr-cli_linux_arm

Note that the latter method will install the `vultr-cli` executable in `builds/vultr-cli_(name of os + arch)`.

### Installing on Arch Linux

```sh
pacman -S vultr-cli
```

### Installing via Brew

```sh
brew install vultr/vultr-cli/vultr-cli
```

### Installing on Fedora

```sh
dnf install vultr-cli
```

### Installing on OpenBSD

```sh
pkg_add vultr-cli
```

### Docker
You can find the image on [Docker Hub](https://hub.docker.com/repository/docker/vultr/vultr-cli). To install the latest version via `docker`:

```sh
docker pull vultr/vultr-cli:latest
```

To pull an older image, you can pass the version string in the tag. For example:
```sh
docker pull vultr/vultr-cli:v2.15.1
```

The available versions are listed [here](https://github.com/vultr/vultr-cli/releases).

As described in the next section, you must authenticate in order to use the CLI. To pass the environment variable into docker, you can do so via:

```sh
docker run -e VULTR_API_KEY vultr/vultr-cli:latest instance list
```

This assumes you've already set the environment variable in your shell environment, otherwise, you can pass it in via `-e VULTR_API_KEY=<your api key>`

## Using Vultr-cli

### Authentication

In order to use `vultr-cli` you will need to export your [Vultr API KEY](https://my.vultr.com/settings/#settingsapi)

`export VULTR_API_KEY=<your api key>`

### Examples

`vultr-cli` can interact with all of your Vultr resources. Here are some basic examples to get you started:

##### List all available instances
`vultr-cli instance list`

##### Create an instance
`vultr-cli instance create --region <region-id> --plan <plan-id> --os <os-id> --host <hostname>`

##### Create a DNS Domain
`vultr-cli dns domain create --domain <domain-name> --ip <ip-address>`

##### Utilizing a boolean flag
You should use = when using a boolean flag.

`vultr-cli instance create --region <region-id> --plan <plan-id> --os <os-id> --host <hostname> --notify=true`

##### Utilizing the config flag
The config flag can be used to specify the vultr-cli.yaml file path when it's outside the default location (default is $HOME/.vultr-cli.yaml). If the file has the `api-key` defined, the CLI will use the vultr-cli.yaml config, otherwise it will default to reading the environment variable for the api key.

`vultr-cli instance list --config /Users/myuser/vultr-cli.yaml`

### Example vultr-cli.yaml config file

Currently the only available field that you can use with a config file is `api-key`. Your yaml file will have a single entry which would be:

`api-key: MYKEY`

### CLI Autocompletion
`vultr-cli completion` will return autocompletions, but this feature requires setup.

Some guides:

<pre>
<h4>Bash:</h4>
  $ source <(vultr-cli completion bash)

  <b>To load completions for each session, execute once:</b>
  <b>Linux:</b>
  $ vultr-cli completion bash > /etc/bash_completion.d/vultr-cli

  <b>macOS:</b>
  $ vultr-cli completion bash > /usr/local/etc/bash_completion.d/vultr-cli

<h4>Zsh:</h4>
  <b>If shell completion is not already enabled in your environment,
  you will need to enable it.  You can execute the following once:</b>

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  <b>To load completions for each session, execute once:</b>
  $ vultr-cli completion zsh > "${fpath[1]}/_vultr-cli"

  You will need to start a new shell for this setup to take effect.

<h4>fish:</h4>
  $ vultr-cli completion fish | source

  <b>To load completions for each session, execute once:</b>
  $ vultr-cli completion fish > ~/.config/fish/completions/vultr-cli.fish

<h4>PowerShell:</h4>
  PS> vultr-cli completion powershell | Out-String | Invoke-Expression

  <b>To load completions for every new session, run:</b>
  PS> vultr-cli completion powershell > vultr-cli.ps1
  <b>and source this file from your PowerShell profile.</b>
</pre>

## Contributing
Feel free to send pull requests our way! Please see the [contributing guidelines](CONTRIBUTING.md).
