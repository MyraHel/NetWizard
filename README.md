# NetWizard

Wannabe swissknife for networking.

## Prerequisites

Make sure you've got libpcap-devel and net-tools installed.

On RedHat distros:

```
sudo yum install libpcap-devel net-tools
```

After the clone, install all required gems.
As a normal user, just:

```
bundle install
```

But, since many commands must run as root, you must install all gems as `root`, too:

```
sudo gem install packetfu require_all coderay method-source pry slop method_source
```

## Usage

`sudo ./nwshell.rb`

[TODO]
