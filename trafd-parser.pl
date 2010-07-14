#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;

my $MAX_ENTRIES		= 104800*1.3;

my $TRAFD_HDR_I_LEN 	= length pack('i');
my $TRAFD_HDR_DATE_FMT	= 'ix4ix4';
my $TRAFD_HDR_DATE_LEN	= length pack($TRAFD_HDR_DATE_FMT);
my $TRAFD_ENTRY_FMT	= 'C10SL2';
my $TRAFD_ENTRY_LEN	= length pack($TRAFD_ENTRY_FMT);

sub process_entries($$);
sub human($);

my %opts=(
	d => undef,
	r => undef,
	p => undef,
	h => undef,
	s => undef,
);
getopts('dhprs', \%opts);

my $fname = shift or die << "EOF";
Usage: $0 [-dhprs] <trafd.ifX> [ipaddr]

trafd.ifX - trafd binary data file with traffic
ipaddr    - count incoming traffic for that ipaddress

Options:
  -d	Show dump information: datetime and how many entries it have
  -r	Show detailed traffic records from dumps
  -h	Usage human form output calculation for specified ipaddr (see above)
  -p	Substitute numeric ip protocols by names in detailed traffic (/etc/protocols)
  -s	Substitute numeric services by names in detailed traffic (/etc/services)

EOF

die "No such file or invalid permissions: $fname\n" unless -r $fname;

my $ipaddr = shift;
my $ipaddr_traffic = 0;

my $protocol = {};
if ($opts{p}) {
	open my $p_fh, "/etc/protocols" or die "Cannot open /etc/protocols: $!\n";
	while(<$p_fh>) {
	    $protocol->{$2} = $1 if /^(\S+)\s+(\d+)/;
	}
	close $p_fh;
}

my $services = {};
if ($opts{s}) {
	open my $s_fh, "/etc/services" or die "Cannot open /etc/services: $!\n";
	while(<$s_fh>) {
	    $services->{$2} = $1 if /^(\S+)\s+(\d+)\//;
	}
	close $s_fh;
}


open my $fh, "<", $fname or die "Cannot open for read $fname: $!\n";
binmode $fh;
my $bytes;

my $i = 0;

while(1) {
	my ($max_entries, $have_entries, $buf);

	if (($bytes = read($fh, $buf, $TRAFD_HDR_I_LEN)) == 0) {
		last; # EOF
	} elsif ($bytes != $TRAFD_HDR_I_LEN) {
		die "Error occured. $fname: Incorrect data structure\n";
	}
	$max_entries = unpack('i', $buf);

	if ($max_entries != $MAX_ENTRIES) {
		# SIGINT - append collected data to savefile
		$have_entries = $max_entries;
		$max_entries = $MAX_ENTRIES;
	} else {
		# SIGHUP - drop collected data to tempfile (dump full table)
		if (($bytes = read($fh, $buf, $TRAFD_HDR_I_LEN)) != $TRAFD_HDR_I_LEN) {
			die "Error occured. $fname: Incorrect data structure\n";
		};
		$have_entries = unpack('i', $buf);
	}

	if (($bytes = read($fh, $buf, $TRAFD_HDR_DATE_LEN)) != $TRAFD_HDR_DATE_LEN) {
		die "Error occured. $fname: Incorrect data structure\n";
	};
	
	my($begin, $end) = unpack($TRAFD_HDR_DATE_FMT, $buf);

	printf "[%d] %s -- %s entries=%d\n",
		$i++,
		scalar(localtime($begin)), 
		scalar(localtime($end)),
		$have_entries, $max_entries if $opts{d};
	
	process_entries($fh, $have_entries);
}

sub process_entries($$) {
	my ($fh, $have_entries) = @_;
	my $buf;

	my ($src_addr, $src_port, $dst_addr, $dst_port, $ip_protocol, $n_psize);
	format =
@<<<<<<<<<<<<<<< @<<<<< @<<<<<<<<<<<<<<< @<<<<< @<<<<<<<<<< @<<<<<<<<<<<<<<<
$src_addr, $src_port, $dst_addr, $dst_port, $ip_protocol, $n_psize
.
	while ($have_entries-- > 0)
	{
		if (($bytes = read($fh, $buf, $TRAFD_ENTRY_LEN)) != $TRAFD_ENTRY_LEN) {
			die "Error occured. $fname: Incorrect data structure\n";
		};

		my ($s1,$s2,$s3,$s4, $d1,$d2,$d3,$d4, $who_srv, $p_port, $n_bytes);
		$src_addr = $src_port = $dst_addr = $dst_port = $ip_protocol = $n_psize = undef;

		($s1,$s2,$s3,$s4,	# src ip addr
		    $d1,$d2,$d3,$d4,	# dst ip addr
	            $ip_protocol,	# which protocol been used (/etc/protocols)
		    $who_srv,		# who was server flag
		    $p_port,		# which port been used (/etc/services)
		    $n_psize,		# how many bytes in ip datagrams passed
		    $n_bytes		# how many data bytes passed
		) = unpack($TRAFD_ENTRY_FMT, $buf);

	        $src_addr = "$s1.$s2.$s3.$s4";
	        $src_port = '';
	        $dst_addr = "$d1.$d2.$d3.$d4";
	        $dst_port = '';

		# ip_protocol: tcp or udp
		if ($ip_protocol == 6 or $ip_protocol == 12) {
			if ($who_srv == 0) {
				$src_port = 0;
				$dst_port = 0;
			} elsif ($who_srv == 1) {
				$src_port = $p_port;
				$dst_port = 0;
			} elsif ($who_srv == 2) {
				$src_port = 0;
				$dst_port = $p_port;
			}
		}
		
		$ip_protocol = $protocol->{$ip_protocol} if $opts{p} && $protocol->{$ip_protocol};

		$src_port = $services->{$src_port} if $opts{s} && $services->{$src_port};
		$dst_port = $services->{$dst_port} if $opts{s} && $services->{$dst_port};

		# we need only to process the records for specified ipaddress
		if ($ipaddr) {
			$ipaddr_traffic += $n_psize if $ipaddr eq $dst_addr;
			next unless $ipaddr eq $src_addr or $ipaddr eq $dst_addr;
		}

		write if $opts{r};
#		printf "%s|%s|%s|%s|%s|%ul\n", $src_addr, $src_port, 
#			$dst_addr, $dst_port, $ip_protocol, $n_psize;
	}	
}

sub human($) {
	my $size = shift;
	my $suffix = '';

	return '0B' if ($size == 0);
	if ($size >= 1024 && $size < 1048576) {
		$suffix = 'K'; $size /= 1024;
	} elsif ($size < 1073741824) {
		$suffix = 'M'; $size /= 1048576;
	} elsif ($size < 1099511627776) {
		$suffix = 'G'; $size /= 1073741824;
	} elsif ($size < 1125899906842624) {
		$suffix = 'T'; $size /= 1099511627776;
	} else {
		$suffix = 'P'; $size /= 1125899906842624;
	}

	return sprintf((($size >= 10) ? "%.0f%s" : "%.1f%s"), $size, $suffix);
}


END {
	printf "Incoming traffic for %s: %s\n", $ipaddr, $opts{h} ? human($ipaddr_traffic) : $ipaddr_traffic if $ipaddr;
};
