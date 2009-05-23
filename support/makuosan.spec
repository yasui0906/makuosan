Name:           makuosan
Version:        1.2.0
Release:        1%{?dist}
Summary:        Multicasts All-Kinds of Updating Operation for Servers on Administered Network

Group:          System Environment/Daemons
License:        GPL
URL:            http://lab.klab.org/wiki/Makuosan
Source0:        http://downloads.sourceforge.net/makuosan/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires: initscripts
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig, /sbin/service
Requires(postun): /sbin/service

%description
Makuosan(MAKUO for short) is a software which transfer files to multiple servers 
simultaneously using UDP multicast.
(MAKUO consists of makuosan daemon and command line utility msync. The makuosan 
should be run on every server in a cluster. The makuo talk to makuosan daemon.)
MAKUO has following features;

 * Scalability
The time required to transfer files to multiple servers does not depend on 
the number of the target servers. 
It takes almost as same amount of time to transfer files to 20 servers 
as it does to 10 servers. However, it is desirable to use MAKUO among servers 
with similar performance, because transfer speed is limited by the slowest server.

 * Simultaneous update on every server.
The makuosan transfers files simultaneously using IP multicast. 
Therefore, there should not be any out of sync server.

 * Simple configuration
Each makuosan daemon maintains available server list by periodically checking 
existence of other makuosan daemons on different servers.
The makuosan transfers files only to those servers where makuosan daemon is 
also alive. Therefore, it never stalls waiting for a dead server, or timeouts.

%prep
%setup -q


%build
%configure --prefix=/usr

make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

# remove memcached-debug
rm -f %{buildroot}/%{_bindir}/makuosan-debug

# Init script
install -Dp -m0755 makuosan.sysv %{buildroot}%{_initrddir}/makuosan

# Default configs
mkdir -p %{buildroot}/%{_sysconfdir}/sysconfig
cat <<EOF >%{buildroot}/%{_sysconfdir}/sysconfig/%{name}
BASE_DIR=""
PORT="5000"
IP_ADDRESS="127.0.0.1"
SOCKET=""
EOF

%clean
rm -rf %{buildroot}


%post

%files
%defattr(-,root,root,-)
%doc AUTHORS ChangeLog COPYING INSTALL NEWS README 
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}

%{_bindir}/msync
%{_sbindir}/makuosan
%{_initrddir}/makuosan


%changelog
* Mon May 25 2009 Masanobu Yasui <yasui0906@gmail.com> - 1.2.0

* Thu Nov  6 2008 Naoya Nakazawa <naoya.n@gmail.com> - 1.0.0
- Initial version

