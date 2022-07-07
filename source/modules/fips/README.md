## FIPS support

This repository contains the following 3rd-party headers and shared libraries
required by the FIPS build of `asd`:

  * SafeLogic's FIPS-compliant version of OpenSSL 1.0.2
  * cURL linked with SafeLogic
  * OpenLDAP linked with SafeLogic

The current versions are:

  * SafeLogic - `102zb`
  * OpenLDAP - `2.5.11`
  * cURL - `7.81.0`

Here's how to use this repository:

  * Clone it into a directory of your choice.

  * Make the `FIPSREPO` environment variable point to your clone. Just like you
    made `EEREPO` point to your clone of the EE repository.

  * Run `make +fips` in the CE repository to build the FIPS version of `asd`.

  * The resulting `asd` executable will have `/opt/aerospike/lib/fips` embedded
    as its shared library search path. That's where the `.deb` and `.rpm`
    packages put the libraries.

    If you don't have a FIPS `.deb` or `.rpm` package installed, you can
    make the dynamic linker pick up the libraries from `${FIPSREPO}/devel/lib`
    instead, via the `LD_LIBRARY_PATH` environment variable.

    For example, in the CE repository's root directory run:

    `LD_LIBRARY_PATH=${FIPSREPO}/devel/lib target/Linux-x86_64/bin/asd`

