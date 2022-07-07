#!/bin/bash
#
#   File:         bin/prep.tcsh
#   Description:  Prepare environment for build from source distribution.
#   Usage:        prompt$ . bin/prep.bash
#

export ASREPO=$PWD/aerospike-server
export CLIENTREPO=$PWD/aerospike-client-c
export EEREPO=$PWD/aerospike-server-enterprise

cp -p client/make_in/version.c{,.KEEP}
mv client/make_in/update_version.sh{,.ORIG}
cat > client/make_in/update_version.sh <<EOF
cp -p version.c{.KEEP,}
EOF
chmod ugo+x client/make_in/update_version.sh

mv aerospike-server/build/gen_version{,.ORIG}
cat > aerospike-server/build/gen_version <<EOF
cat version.c
EOF
chmod ugo+x aerospike-server/build/gen_version

mv aerospike-server/build/version{,.ORIG}
grep build_id aerospike-server/version.c | sed 's/.*\"\(.*\)\";/echo \1/' > aerospike-server/build/version
chmod ugo+x aerospike-server/build/version

mkdir -p client/shared/{include/citrusleaf,lib}

mkdir -p client/{test,tools}
cat > client/test/Makefile <<EOF
all clean:
EOF
cp -p client/test/Makefile client/tools/
