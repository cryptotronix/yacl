#
# Spec file for yacl
#
Name: yacl
Version: 0.0.3
Release: 0
Summary: yacl library
License: see %{pkgdocdir}/copyright

%define packagebase yacl-0.3

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
%configure
make CFLAGS="$RPM_OPT_FLAGS"


%install
rm -rf %{buildroot}
make install-strip DESTDIR=%{buildroot}
# Clean out files that should not be part of the rpm.
%{__rm} -f %{buildroot}%{_libdir}/%{name}/*.la


%post
-p /sbin/ldconfig

%preun

%postun
-p /sbin/ldconfig

%posttrans

%clean
%{__rm} -rf %{buildroot}

%files
%defattr( -, root, root )
# %define _prefix /
%{_libdir}/pkgconfig/yacl.pc
%{_includedir}/*
%{_libdir}/*.so

%files static
%defattr(-,root,root)
%{_libdir}/*.a
