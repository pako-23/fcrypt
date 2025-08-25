# Development Environment Setup
This is a C project built with Autotools. The following document
guides through a development environment setup.


## Prerequisite: Install Build Essentials
Before you can build a C project, your system needs the fundamental
tools for compilation and scripting. These are typically bundled
together in a "build essentials" or "development tools" package.

### Linux (Debian/Ubuntu)
You can install the required tooling by issuing the following command
in a shell:

```shell
sudo apt-get install build-essential
```

### Linux (Fedora/CentOS)
You can install the required tooling by issuing the following command
in a shell:

```shell
sudo dnf groupinstall "Development Tools"
```

### MacOS
The development tooling can be installed by issuing the following
command in a shell:

```shell
xcode-select --install
```

## Install Autotools
Autotools consists of several key programs: Autoconf, Automake, and
Libtool. These are necessary to generate the configure script and
Makefiles from the project's source files.

### Linux (Debian/Ubuntu)
You can install Autotools by issuing the following command in a shell:

```shell
sudo apt-get install autoconf automake libtool
```

### Linux (Fedora/CentOS)
You can install Autotools by issuing the following command in a shell:

```shell
sudo dnf install autoconf automake libtool
```

### MacOS
The Autotools be installed by issuing the following command in a
shell:

```shell
brew install autoconf automake libtool
```

The command assumes that you already have `brew` installed. If that is
not the case you can install `brew` by following the steps described
[here](https://brew.sh/).


## Install the Check Testing Framework
To run the tests that come with the project, you will have to install
the [Check Testing Framework](https://libcheck.github.io/check/).

### Linux (Debian/Ubuntu)
You can install Check by issuing the following command in a shell:

```shell
sudo apt-get install check
```

### Linux (Fedora/CentOS)
You can install Check by issuing the following command in a shell:

```shell
sudo dnf install check
```

### MacOS
You can install Check by issuing the following command in a shell:

```shell
brew install check
```

## Configure the Build
Before you can build the project, you will have to generate the
configuration and build scripts.  You can generate the configuration
scripts by running the `bootstrap.sh` script.  Therefore, generate the
configuration scripts as follows:

```shell
./bootstraph.sh
```

Finally, we can configure and build the project in a separate folder
as follows:

```shell
mkdir build
cd build
../configure
make
```
Once built, you can also run the tests on the project as follows:

```shell
make check
```
