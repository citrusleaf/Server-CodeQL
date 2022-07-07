#!/bin/bash

set -e -u -o pipefail

BASE=$(pwd)

rm -rf ${BASE}/build /opt/aerospike ${BASE}/devel
mkdir ${BASE}/devel

export CPPFLAGS=-I${BASE}/devel/include
export LDFLAGS="-Wl,-rpath=/opt/aerospike/lib/fips -L${BASE}/devel/lib"

export LD_LIBRARY_PATH=${BASE}/devel/lib

# extract SafeLogic's libraries to devel

cd ${BASE}/devel
tar zxvf ${BASE}/binary/openssl102zb-linux-x86_64.tar.gz

mv ${BASE}/devel/LICENSE ${BASE}/devel/OPENSSL-LICENSE

# otherwise, pkg-config will make cURL go look for OpenSSL in /usr/local

rm -rf ${BASE}/devel/lib/pkgconfig

# build cURL, install to /opt/aerospike, copy relevant files to devel

mkdir ${BASE}/build
cd ${BASE}/build

${BASE}/source/curl/configure \
    --prefix=/opt/aerospike \
    --disable-ares \
    --disable-static \
    --enable-http \
    --disable-ftp \
    --disable-file \
    --disable-ldap \
    --disable-ldaps \
    --disable-rtsp \
    --disable-proxy \
    --disable-dict \
    --disable-telnet \
    --disable-tftp \
    --disable-pop3 \
    --disable-imap \
    --disable-smb \
    --disable-smtp \
    --disable-gopher \
    --disable-mqtt \
    --disable-sspi \
    --disable-manual \
    --disable-doh \
    --disable-netrc \
    --disable-hsts \
    --with-openssl \
    --without-hyper \
    --without-brotli \
    --without-zstd \
    --without-gssapi \
    --with-openssl=${BASE}/devel \
    --with-default-ssl-backend=openssl \
    --without-libpsl \
    --without-libgsasl \
    --without-libssh2 \
    --without-libssh \
    --without-librtmp \
    --without-libidn2 \
    --without-nghttp2 \
    --without-ngtcp2 \
    --without-nghttp3 \
    --without-quiche

make
make install

cd ${BASE}
rm -rf ${BASE}/build

mkdir ${BASE}/devel/include/curl

cp -d /opt/aerospike/include/curl/* ${BASE}/devel/include/curl
cp -d /opt/aerospike/lib/lib* ${BASE}/devel/lib

rm -rf /opt/aerospike

cp ${BASE}/source/curl/COPYING ${BASE}/devel/CURL-COPYING

# build OpenLDAP, install to /opt/aerospike, copy relevant files to devel

mkdir ${BASE}/build
cd ${BASE}/build

${BASE}/source/openldap/configure \
    --prefix=/opt/aerospike \
    --disable-slapd \
    --disable-balancer \
    --disable-static \
    --without-cyrus-sasl \
    --without-systemd \
    --without-fetch \
    --with-tls=openssl \
    --without-mp

make depend
make
make install

cd ${BASE}
rm -rf ${BASE}/build

cp -d /opt/aerospike/include/* ${BASE}/devel/include
cp -d /opt/aerospike/lib/lib* ${BASE}/devel/lib

rm -rf /opt/aerospike

cp ${BASE}/source/openldap/COPYRIGHT ${BASE}/devel/OPENLDAP-COPYRIGHT
cp ${BASE}/source/openldap/LICENSE ${BASE}/devel/OPENLDAP-LICENSE

# fix DT_RUNPATH

cd ${BASE}/devel

chmod 755 bin/openssl
patchelf --set-rpath /opt/aerospike/lib/fips bin/openssl
