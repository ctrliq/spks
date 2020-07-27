![CI](https://github.com/ctrl-cmd/spks/workflows/ci/badge.svg)

# Singularity Public Key Server #

Singularity PKS allows to store and retrieve user public PGP keys. Unlike traditional public key servers each submitted key goes through a validation process via mail addresses and force users to have a valid identity associated to their public PGP keys.

## Features ##

* Key validation process based on mail addresses and domain filtering
* Server signing of public PGP keys identity (Web of Trust)

## Restrictions compared to traditional key servers ##

* No synchronization or shared database with a pool of servers
* Only one identity per key

## Installation ##

```
git clone https://github.com/ctrl-cmd/spks && cd spks/build
go run mage.go build
./spks
```

## Create and install from package ##

* Deb package:

  ```
  go run mage.go package:deb
  sudo dpkg -i release/$(git describe|sed 's/^v//')/*.deb
  ```

* RPM package:

  ```
  go run mage.go package:deb
  sudo rpm -ivh release/$(git describe|sed 's/^v//')/*.rpm
  ```

## Configuration ##

By default server is searching for a configuration file in `/usr/local/etc/spks/server.yaml`, if not found the server will start with a default configuration which should be pretty limited for your environment.

To see available configuration directives, you can refer to this [configuration file example](etc/server-example.yaml)
