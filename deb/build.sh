#!/bin/bash

set -eu

NAME=auth2
BIN_PATH=$1
VERSION=$2
ARCH=$3
DEB_SRC="deb-${VERSION}-${ARCH}"
DEB_NAME="${NAME}_${VERSION}_${ARCH}.deb"

mkdir "${DEB_SRC}"
install -Dm755 "${BIN_PATH}" "${DEB_SRC}/usr/bin/${NAME}"
install -Dm644 "deb/env" "${DEB_SRC}/etc/${NAME}/env"
install -Dm644 "deb/${NAME}.service" "${DEB_SRC}/lib/systemd/system/${NAME}.service"
install -Dm644 "deb/${NAME}.7" "${DEB_SRC}/usr/share/man/man7/${NAME}.7"
install -Dm644 README.md "${DEB_SRC}/usr/share/doc/${NAME}/README.md"
install -Dm644 deb/changelog "${DEB_SRC}/usr/share/doc/${NAME}/changelog"
install -Dm644 deb/copyright "${DEB_SRC}/usr/share/doc/${NAME}/copyright"
sed 's/^/ /g' LICENSE >> "${DEB_SRC}/usr/share/doc/${NAME}/copyright"
gzip -n --best "${DEB_SRC}/usr/share/man/man7/${NAME}.7"
gzip -n --best "${DEB_SRC}/usr/share/doc/${NAME}/changelog"

install -Dm755 deb/postinst "${DEB_SRC}/DEBIAN/postinst"
install -Dm644 deb/conffiles "${DEB_SRC}/DEBIAN/conffiles"
install -Dm644 deb/control "${DEB_SRC}/DEBIAN/control"
sed -i "s/^Version:.*/Version: ${VERSION}/1" "${DEB_SRC}/DEBIAN/control"
sed -i "s/Architecture:.*/Architecture: ${ARCH}/1" "${DEB_SRC}/DEBIAN/control"

fakeroot dpkg-deb --build "${DEB_SRC}" "${DEB_NAME}"
lintian "${DEB_NAME}"

rm -r "${DEB_SRC}"
