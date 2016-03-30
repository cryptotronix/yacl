#!/bin/bash
PACKAGE=$1
VERSION=$2

if [ $# -eq 0 ]; then
    echo "Usage: $0 package version"
    exit 1
fi

is_ok() {
    if [ $? -ne 0 ]; then
        echo "Died at $1"
        exit 1
    fi
    echo "$1 OK"
}

#if BUILDING_DEB
DEBSOURCEPKG="$PACKAGE"_"$VERSION".orig.tar.gz
DEBSOURCEDIR=$PACKAGE-$VERSION

rm $DEBSOURCEPKG
rm -rf $DEBSOURCEDIR

echo "Building debian package with systemd"

cp $PACKAGE-$VERSION.tar.gz $DEBSOURCEPKG
is_ok "move package"

tar --extract --gunzip --file $DEBSOURCEPKG
is_ok "extract package"


mkdir -p $DEBSOURCEDIR/debian
is_ok "mkdir debian"

cp debian/changelog \
   debian/compat \
   debian/control \
   debian/copyright \
   debian/docs \
   debian/rules \
   $DEBSOURCEDIR/debian
is_ok "copy deb files"

# cp wiauthd.service $DEBSOURCEDIR/debian
# is_ok "copy service"
# cp wiauthd.socket $DEBSOURCEDIR/debian
# is_ok "copy socket"

mkdir -p $DEBSOURCEDIR/debian/source
is_ok "mkdir source"

cp debian/source/format $DEBSOURCEDIR/debian/source
is_ok "cp format"

cd $DEBSOURCEDIR
eval "$CONFIGURE_CMD"
is_ok "configure"

DEB_BUILD_MAINT_OPTIONS=hardening=-format dpkg-buildpackage -us -uc;
is_ok dpkg-buildpackage

cd ..
rm --force $DEBSOURCEPKG;
is_ok "rm $DEBSOURCEPKG"

rm --recursive --force $DEBSOURCEDIR
is_ok "rm $DEBSOURCEDIR"

rm *.changes
is_ok "rm changes"

rm *.dsc
is_ok "rm dsc"

rm *.xz
is_ok "rm xz"
