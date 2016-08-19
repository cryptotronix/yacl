#
# Spec file for yacl
#
%define _prefix /usr
%define _libdir %{_prefix}/lib64

Name: yacl
Version: 1.1.1
Release: 0
Summary: yacl library
License: see %{pkgdocdir}/copyright

%define packagebase yacl-1.1.1

Group: System Environment/Libraries
Source: %{packagebase}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Small library for basic crypto primitives

%package devel
Summary: Development files for libyacl
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
This package contains the header files, libraries  and documentation needed to
develop applications that use libyacl.

%package static
Summary: Static development files for libyacl
Group: Development/Libraries
Requires: %{name}-devel = %{version}-%{release}

%description static
This package contains static libraries to develop applications that use yacl.

%prep
%setup -n %{packagebase}

%build
%configure --with-guile --with-libsodium --with-libglib

make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install-strip DESTDIR=%{buildroot}
# Clean out files that should not be part of the rpm.
%{__rm} -f %{buildroot}/usr/lib64/*.la


%post
/sbin/ldconfig

%preun

%postun
/sbin/ldconfig

%posttrans

%clean
%{__rm} -rf %{buildroot}

%files
%defattr( -, root, root )
#%define _prefix /
/usr/lib64/pkgconfig/yacl.pc
/usr/include/yacl-1.1/*
/usr/lib64/*.so
/usr/lib64/*.so.*
/usr/share/guile/site/2.0/cryptotronix/*

%files static
%defattr(-,root,root)
/usr/lib64/*.a
