# Aerospike Server - Enterprise Edition

This repo. contains the "overbox" code implementing the Aerospike Server
Enterprise Edition features.

## Prerequisites

To build the Aerospike Server Enterprise Edition, clone this repo.
("citrusleaf/aerospike-server-enterprise") and the Aerospike Server
repo. ("citrusleaf/aerospike-server") locally. In both repos, make sure 
you have pulled the submodules.

Then set the `EEREPO` environment variable to point to the local clone of
this repo. 

## Usage

### Build Options

#### Enterprise Edition Feature Support

To build the Aerospike server with all of the Enterprise Edition features, 
execute the following command from
within the local clone of the Aerospike Server repo.:

	$ make +ee

#### Remove Build Products

To remove all build products (excluding packages), use:

	$ make clean+ee

To remove all built packages, use:

	$ make cleanpkg

To remove all build products (including packages), use:

	$ make cleanall

#### Packaging

To package a build with Enterprise Edition features, first do a build
with Enterprise Edition features, then use one of the following:

	$ make deb+ee    --  Build a Debian package with Enterprise Edition features.

	$ make rpm+ee    --  Build a RPM package with Enterprise Edition features.

	$ make strip+ee  --  Build a "strip(1)"ed version of the Enterprise Edition server executable.

	$ make tar+ee    --  Build a compresed "tar" archive with Enterprise Edition features.

#### Source Distribution

To create a source distribution `tar` file, use:

	$ make source+ee
