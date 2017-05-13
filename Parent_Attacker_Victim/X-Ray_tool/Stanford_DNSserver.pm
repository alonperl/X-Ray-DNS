
package Stanford_DNSserver;

use strict;


use POSIX;
use IO::Socket;
use IO::Select;
use Stanford_DNS;
use Sys::Hostname;

sub new {
    my ($class, %args) = @_;

    my $self = {
                listen_on => $args{listen_on} || [hostname()],
                port      => $args{port}      ||           53,
                defttl    => $args{defttl}    ||         3600,
                debug     => $args{debug}     ||            0,
                daemon    => $args{daemon}    ||        "yes",
                pidfile   => $args{pidfile}   ||        undef,
                chroot    => $args{chroot}    ||        undef,
                run_as    => $args{run_as}    ||        undef,
                logfunc   => $args{logfunc}   ||        undef,
                loopfunc  => $args{loopfunc}  ||        undef,
                exitfunc  => $args{exitfunc}  ||        undef,
                dontwait  => $args{dontwait}  ||        undef
               };
    $self->{select} = new IO::Select;
    bless $self, $class;
    return $self;
}

sub add_static {
    my ($self, $domain, $type, $value, $ttl) = @_;

    $ttl = $self->{defttl} unless defined $ttl;

    $self->{static}->{$domain}->{$type}->{answer}  .= dns_answer(QPTR, $type, C_IN, $ttl, $value);
    $self->{static}->{$domain}->{$type}->{ancount} += 1;
}

sub add_dynamic {
    my ($self, $domain, $handler) = @_;
    $self->{dynamic}->{$domain} = $handler;
}

sub answer_queries {
    my $self = shift;

    $self->daemon() unless lc($self->{daemon}) eq "no";

    $self->init();

    $self->writepid() if $self->{pidfile};
    $self->cdchroot() if $self->{chroot};
    $self->chguid()   if $self->{run_as};

    my $run = ref($self->{loopfunc}) =~ /^CODE/;
    my $UDP = getprotobyname('udp') or $self->abort("can't get udp: $!");
    my $TCP = getprotobyname('tcp') or $self->abort("can't get tcp: $!");

    while (1) {
        &{$self->{loopfunc}} if $run;

        foreach ($self->{select}->can_read(600)) {
            $self->handle_udp_req($_) if $_->protocol == $UDP;
            $self->handle_tcp_req($_) if $_->protocol == $TCP;
        }
    }
}

sub handle_udp_req {
    my $self = shift;
    my $sock = shift;
    my $buff;

    $sock->recv( $buff, 8192, 0)
      or $self->log("handle_udp_req: recv: $!");
    my ($reply,$do_send,$delay) = $self->do_dns_request($buff, $sock);
	
    if ($reply and $do_send) {
		if ($delay>0)
		{
			select(undef, undef, undef, $delay);
		}
        $sock->send($reply, 0)
          or $self->log("handle_udp_req: send: $!");
    }
}

sub handle_tcp_req {
    my $self = shift;
    my $sock = shift;
    my $from;

    $self->log('entering handle_tcp_req') if $self->{debug} > 1;

    if (not ($from = $sock->accept)) {
        $self->log("handle_tcp_req: accept: $!");
        return;
    }

    if (fork) {         # parent
        $from->close();
    } else {            # child
        my $buff;
        foreach ($self->{select}->handles()) { $_->close() }
        while ($from->sysread($buff, 2)) {
            my $len = unpack('n', $buff);   # TCP header
            $from->sysread($buff, $len) or $self->abort("handle_tcp_req: sysread: $!");
            my ($reply,$do_send,$delay) = $self->do_dns_request($buff, $from, 1);
            if ($reply and $do_send) {   # add 2 byte TCP header
				if ($delay>0)
				{
					select(undef, undef, undef, $delay);
				}
                $from->send(pack('n', length $reply) . $reply, 0)
                  or $self->abort("handle_tcp_req: send: $!");
            }
        }
        exit 0;
    }
}

sub do_dns_request {
    my ($self, $buff, $sock, $usingtcp) = @_;
    my $from = $sock->peerhost();
	my $from_port = $sock->peerport();
    my ($header, $question, $ptr);

    my $buff_len = length $buff;
    if ($buff_len <= HEADERLEN())  # short packet, ignore it.
	{
		$self->log("MALFORMED Query (incomplete headers) from $from:$from_port") if $self->{debug};
		return ('',0,0);
	}

    $header   = substr($buff, 0, HEADERLEN());
	my ($question_domain, $end_offset)=dn_expand(\$buff,HEADERLEN());
    $question = substr($buff, HEADERLEN(),$end_offset-HEADERLEN()+4);  # include CLASS and TYPE
    $ptr      = HEADERLEN();

    my ($id, $flags, $qdcount, $ancount, $aucount, $adcount) = unpack('n6C*', $header);

    my $opcode  = ($flags & OP_MASK) >> OP_SHIFT;
    my $qr      = ($flags & QR_MASK) >> QR_SHIFT;  # query/response
    my $tc      = ($flags & TC_MASK) >> TC_SHIFT;  # truncation
    my $rd      = ($flags & RD_MASK) >> RD_SHIFT;  # recursion desired

    if ($qr)  # should not be set on a query, ignore packet
	{
		$self->log("MALFORMED Query (QR bit is 1 - response) from $from:$from_port")  if $self->{debug};
			   
		return ('',0,0);
	}
	
    if ($opcode != QUERY) {
		$self->log("MALFORMED Query (opcode is not QUERY) from $from:$from_port")  if $self->{debug};
	
        $flags |= QR_MASK | AA_MASK | NOTIMP;
        return (pack('n6', $id, $flags, 1, 0, 0, 0) . $question,1,0);
    }

    my $qname;
    ($qname, $ptr) = dn_expand(\$buff, $ptr);
    if (not defined $qname) {
			$self->log("MALFORMED Query (error parsing question) from $from:$from_port")  if $self->{debug};

        $flags |= QR_MASK | AA_MASK | FORMERR;
        return (pack('n6', $id, $flags, 1, 0, 0, 0) . $question,1,0);
    }

    my ($qtype, $qclass) = unpack('nn', substr($buff, $ptr, 4));
    $ptr += 4;

    $qname = lc($qname);

	if (($qdcount!=1) or ($ancount>0) or ($aucount>0) or ($adcount>1))
	{
		$self->log("MALFORMED Query (unexpected field/count): $qname " . $Type2A{$qtype} .
               ' ' . $Class2A{$qclass} . " from $from:$from_port")  if $self->{debug};

        $flags |= QR_MASK | AA_MASK | FORMERR;
        return (pack('n6', $id, $flags, 1, 0, 0, 0) . $question,1,0);
    }

    my %dnsmsg = (
                  rcode   => NOERROR,
                  qdcount => $qdcount,
                  ancount => 0,
                  aucount => 0,
                  adcount => 0,
                  answer  => '',  # response sections
                  auth    => '',
                  add     => '',
				  extra_padding => '',
				  do_send  => 1,
				  delay   => 0
                 );

	$dnsmsg{query}={};
	$dnsmsg{query}{from}=$from;
	$dnsmsg{query}{from_port}=$from_port;
	$dnsmsg{query}{to}=$sock->sockhost();
	$dnsmsg{query}{qid}=$id;
	$dnsmsg{query}{qname}=$qname;
	$dnsmsg{query}{qtype}=$qtype;
	$dnsmsg{query}{qclass}=$qclass;
	$dnsmsg{query}{opcode}=$opcode;
	$dnsmsg{query}{qr}=$qr;
	$dnsmsg{query}{tc}=$tc;
	$dnsmsg{query}{rd}=$rd;
	
	my $edns_debug="";
	my $edns_query=0;
	if (($adcount>0) and (substr($buff,$ptr,1) eq "\0") and (unpack('n',substr($buff,$ptr+1,2)) eq T_OPT()))
	{
		$dnsmsg{query}{edns}={};
		$dnsmsg{query}{edns}{udp_payload_size}=unpack('n',substr($buff,$ptr+3,2));
		$dnsmsg{query}{edns}{extended_rcode}=ord(substr($buff,$ptr+5,1));
		$dnsmsg{query}{edns}{version}=ord(substr($buff,$ptr+6,1));
		my $z0=unpack('n',substr($buff,$ptr+7,2));
		$dnsmsg{query}{edns}{do}=($z0>>15)&1;
		$dnsmsg{query}{edns}{z}=$z0&0x7FFF;
			
		$edns_debug="w/EDNS(0)";
		my $dataend=$ptr+11+unpack('n',substr($buff,$ptr+9,2));
		$ptr+=11;
		while ($ptr<$dataend)
		{
			my $option_code=unpack('n',substr($buff,$ptr,2));
			$ptr+=2;
			my $option_length=unpack('n',substr($buff,$ptr,2));
			$ptr+=2;
			my $option_data=substr($buff,$ptr,$option_length);
			$ptr+=$option_length;
			$dnsmsg{query}{edns}{data}{$option_code}=$option_data;
		}
		
		if ($ptr!=$dataend)
		{ 
			# Malformed data
			$self->log("MALFORMED Query (overflow in EDNS): $qname " . $Type2A{$qtype} .
               ' ' . $Class2A{$qclass} . " from $from:$from_port $edns_debug")  if $self->{debug};
			
			$flags |= QR_MASK | AA_MASK | FORMERR;
			return (pack('n6', $id, $flags, 1, 0, 0, 0) . $question,1,0);
		}
    }
			
	if ($ptr != $buff_len) {  # we are not at end of packet (we should be :-) )
			$self->log("MALFORMED Query (superfluous data at the end of the query): $qname " . $Type2A{$qtype} .
               ' ' . $Class2A{$qclass} . " from $from:$from_port $edns_debug")  if $self->{debug};

		$flags |= QR_MASK | AA_MASK | FORMERR;
        return (pack('n6', $id, $flags, 1, 0, 0, 0) . $question,1,0);
    }

    #$self->log("Query: $qname " . $Type2A{$qtype} .
    #           ' ' . $Class2A{$qclass} . " from $from:$from_port $edns_debug")  if $self->{debug};

		
    if ($self->check_static ($qname,$qtype,$qclass,\%dnsmsg) or
        $self->check_dynamic($qname,$qtype,$qclass,\%dnsmsg,$from)) {
        $flags |= QR_MASK | AA_MASK | $dnsmsg{rcode};
    } else {
        $flags |= QR_MASK | $dnsmsg{rcode};
    }

	# Override AA with data in $dnsmsg if present
	if (defined $dnsmsg{aa})
	{
		$flags &= (0xFFFF^AA_MASK);
		if ($dnsmsg{aa})
		{
			$flags |= AA_MASK;
		}
	}
	
	if ($dnsmsg{rcode} eq DROP())
	{
		return ("",0,0);
	}
	
    # build the response packet, truncating if necessary
    my $reply = $question . $dnsmsg{answer} . $dnsmsg{auth} . $dnsmsg{add} . $dnsmsg{extra_padding};
	
	if (length($reply)> (PACKETSZ - HEADERLEN()))
	{
		$self->log("*** UDP answer for $Type2A{$qtype} $qname: size > 512 (possibly truncating)\n");
	}
	elsif (length($reply)>=(PACKETSZ - HEADERLEN()-12))
	{
		$self->log("WARNING: UDP answer for $Type2A{$qtype} $qname: size >= 500 (size is ".(length($reply)+HEADERLEN())."\n");
	}
	
	
    if (length $reply > (PACKETSZ - HEADERLEN()) and not $usingtcp) {
        $flags |= TC_MASK;
        $reply = substr($reply, 0, (PACKETSZ - HEADERLEN()));
    }
    return (pack('n6', $id, $flags, $qdcount, $dnsmsg{ancount},
                $dnsmsg{aucount}, $dnsmsg{adcount}) . $reply, $dnsmsg{do_send}, $dnsmsg{delay});
}

sub check_static {
    my ($self, $qname, $qtype, $qclass, $dnsmsg) = @_;

    # C_IN is the only class supported for static
    return 0 if ($qclass != C_IN and $qclass != C_ANY);

	return 0 if (not defined $self->{static}->{$qname});
	
    my @answers;
    if ($qtype == T_ANY) {
        foreach my $types ($self->{static}->{$qname}) {
            return 0 unless $types;
            push @answers, $_ foreach (values %$types);
        }
    } else {
        @answers = $self->{static}->{$qname}->{$qtype};
    }

    my $answersnum = 0;
    foreach my $rr (@answers) {
        next unless defined $rr;
        $dnsmsg->{answer} .= $rr->{answer};
        $answersnum = ($dnsmsg->{ancount} += $rr->{ancount});
    }
    return $answersnum;
}

sub check_dynamic {
    my ($self, $qname, $qtype, $qclass, $dnsmsg, $from) = @_;
    my (@atoms, $domain, $dfunc, $residual);

    @atoms = split(/\./, '.' . $qname);
    while (@atoms) {
        if ($residual) { $residual .= '.' . shift @atoms; }
        else           { $residual  =       shift @atoms; }
        $domain = join('.', @atoms);
        last if $dfunc = $self->{dynamic}->{$domain};
    }

    return 0 unless $dfunc;

    &$dfunc($domain, $residual, $qtype, $qclass, $dnsmsg, $from);
    return 1;  # we're authoritative, so we must return true
}

sub init {
    my ($self) = @_;

	if (not $^O=~/win/i)
	{
		$::SIG{INT} = $::SIG{QUIT} = $::SIG{TERM} = sub { $self->do_exit };
		$::SIG{CHLD} = \&_REAPER unless $self->{dontwait};
	}

    foreach (@{$self->{listen_on}}) {

        my $u = new IO::Socket::INET LocalAddr => $_,
                                     LocalPort => $self->{port},
                                     Proto     => 'udp'
          or $self->abort("socket(udp): $!");

        my $t = new IO::Socket::INET LocalAddr => $_,
                                     LocalPort => $self->{port},
                                     Proto     => 'tcp',
                                     Listen    => 20,
                                     Reuse     => 1
          or $self->abort("socket(tcp): $!");

        $self->{select}->add($u);
        $self->{select}->add($t);

        $self->log("listening on [$_:" . $self->{port} . "]");
    }
}

sub daemon {
	if ($^O=~/win/i)
	{
		die "Daemon mode is not supported in Windows";
	}
    my $self = shift;

    exit 0 if fork;
    POSIX::setsid() or $self->abort("cannot detach from controlling terminal");
    exit 0 if fork;

    close(STDIN);
    close(STDOUT);
    close(STDERR);

    open(STDIN,  "+>/dev/null");
    open(STDOUT, "+>&STDIN");
    open(STDERR, "+>&STDIN");
}

# must be called after init() and daemon()
sub writepid {
    my $self = shift;
    my $file = $self->{pidfile};

    local(*PID);

    open(PID,">$file") or $self->abort("Can't open PID file: $file: $!");
    print PID "$$\n";
    close(PID);
}

# must be called after init() and daemon()
sub cdchroot {
    my $self = shift;
    my $dir  = $self->{chroot};

    chdir $dir or $self->abort("chdir($dir): $!");
    chroot '.' or $self->abort("chroot(.): $!");
    $self->log("chroot($dir) successful");
}

# must be called after cdchroot()
sub chguid {
    my $self = shift;
    my $user = $self->{run_as};

    ($>,$)) = ($<,$() = (getpwnam($user))[2,3];
    $self->abort("could not run as $user") if ($> == 0 or $< == 0 or $) == 0 or $( == 0);
    $self->log("running as $user (UID=$<, GID=$()");
}

sub log {
    my ($self, $msg) = @_;
    &{$self->{logfunc}}($msg) if ref($self->{logfunc}) =~ /^CODE/;
	#print "Leaving log with msg=$msg\n";
}

sub abort {
    my ($self, $msg, $status) = @_;
    $self->log('Aborting: ' . $msg);
    $status ||= 1;
    $self->do_exit($status);
}

sub do_exit {
    my ($self, $status) = @_;
    $self->log('shutting down');
    &{$self->{exitfunc}} if ref($self->{exitfunc}) =~ /^CODE/;
    exit $status;
}

sub _REAPER { wait() }


1;
__END__

=head1 NAME

Stanford::DNSserver - A DNS Name Server Framework for Perl.

=head1 SYNOPSIS

  use Stanford::DNSserver;

  $ns = new Stanford::DNSserver;

  $ns->add_static($domain, $type, $value, $ttl);
  $ns->add_dynamic($domain, $handler);

  $ns->answer_queries();

=head1 DESCRIPTION

B<Stanford::DNSserver> is a DNS name server framework.  It allows you to
make any information accessible with perl available via DNS.  To put
it another way, it's a name server with a perl back end.

=head1 METHODS

B<new> [ I<%arguments> ]

Allocates and returns a new B<Stanford::DNSserver> object.  The optional
I<arguments> can be used to tailor how the name server works.  Here
they are:

=over

=item * B<listen_on> =E<gt> I<\@interfaces>

A reference to an array of interfaces to listen on.  Interfaces can be
specified by name or IP address.  If I<listen_on> is not specified, the
host name is used.

=item * B<port> =E<gt> I<PORT>

The port to listen on.  The default is 53.

=item * B<defttl> =E<gt> I<SECONDS>

The default time to live value for answers given out by the name
server.  The default is 3600 seconds.

=item * B<debug> =E<gt> I<LEVEL>

The debug level.

=item * B<daemon> =E<gt> I<'yes'> | I<'no'>

Tells whether the name server should become a detached daemon.  The
default is 'yes'.

=item * B<pidfile> =E<gt> I<FILENAME>

File in which to store the process ID of the name server process.  No
file is created unless this argument is present.

=item * B<logfunc> =E<gt> I<\&function>

A reference to a function taking a single string argument.  This
function is called with any messages the name server logs.  No logging
is performed unless this argument is present.

=item * B<loopfunc> =E<gt> I<\&function>

A reference to a function to run every time through the inner server
loop, i.e. for each query or every 10 minutes if there are no queries.
Use this to do any periodic maintenance.

=item * B<exitfunc> =E<gt> I<\&function>

A reference to a function to run when the name server exits.  Use this
for any final cleanup.  Note that B<Stanford::DNSserver> catches B<INT>,
B<QUIT>, and B<TERM> signals, so providing an B<exitfunc> is the only
way to clean up when any of those signals are received.

=item * B<dontwait> =E<gt> I<0> | I<1>

B<Stanford::DNSserver> forks to handle TCP DNS queries.  It catches
B<SIGCHLD> in order to wait(3) for these processes.  Setting
B<dontwait> to I<1> tells B<Stanford::DNSserver> I<not> to catch
B<SIGCHLD> nor wait for those forked processes.  Use B<dontwait> when
your program provides a B<SIGCHLD> handler - just be sure to wait(3)
for the forked TCP processes.

=back

B<add_static> I<$domain, $type, $value, $ttl>

Add a domain with the specified properties to the DNS server.  When
the DNS server is queried for this domain it will respond with the
given answer.

B<add_dynamic> I<$domain, $handler>

Add a domain with the specified handler to the DNS server.  When the
DNS server is queried for any name in this domain, it runs the
specified handler as follows:

S<&$handler($domain, $residual, $type, $class, $dnsmsg, $from);>

where

=over

=item *

I<$domain> is the domain in the query.

=item *

I<$residual> is the name in the query.

=item *

I<$type> is the type of the query.

=item *

I<$class> is the class of the query.

=item *

I<$dnsmsg> is a pointer to the DNS message.  The handler may add
answers and/or authority records to the DNS message using functions
from the B<Stanford::DNS> module.

=item *

I<$from> is the name or IP address of the system that made the query.

=back

B<answer_queries>

Start listening for DNS queries and answer them as specified by
previous calls to B<add_static> and B<add_dynamic>.

=head1 CONTRIBUTIONS

B<Stanford::DNSserver> is based on B<lbnamed> by Roland Schemers.
Initial transformation from B<lbnamed> into B<Stanford::DNSserver> by
Marco d'Itri.  Multiple interface support by Dan Astoorian.  Further
suggestions and code from Aidan Cully and Mike Mitchell.  Module name
suggested by Ivan Kohler.  Integration, modernization, documentation
and final assembly by Rob Riepel.

=head1 SEE ALSO

Stanford::DNS

=cut
