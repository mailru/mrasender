Name: tarantool-mrasender
Version: 1.0.1
Release: 1%{?dist}
Summary: Templates for Tarantool modules
Group: Applications/Databases
License: BSD
URL: https://github.com/tarantool/mrasender
Source0: https://github.com/tarantool/%{name}/archive/%{version}/%{name}-%{version}.tar.gz
BuildRequires: cmake >= 2.8
BuildRequires: gcc >= 4.5
BuildRequires: tarantool-devel >= 1.6.8.0
BuildRequires: msgpuck-devel >= 1.0.0
BuildRequires: /usr/bin/prove
Requires: tarantool >= 1.6.8.0

%description
This package provides send message to Mail.Ru Agent from Tarantool.

%prep
%setup -q -n %{name}-%{version}

%build
%cmake . -DCMAKE_BUILD_TYPE=RelWithDebInfo
make %{?_smp_mflags}

%check
make %{?_smp_mflags} check

%install
%make_install

%files
%{_libdir}/tarantool/*/
%{_datarootdir}/tarantool/*/
%doc README.md
%{!?_licensedir:%global license %doc}
%license LICENSE AUTHORS

%changelog
* Thu Apr 26 2016 Maxim Glekov <m.glekov@corp.mail.ru> 1.0.1
- Initial version of the RPM spec
