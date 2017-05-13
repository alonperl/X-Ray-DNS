use Stanford_DNSserver;
use Stanford_DNS;
use Getopt::Long;
use Sys::Hostname;
use Time::HiRes qw(time);

$random_drop_one=0;
$random_drop_two=0;
$random_drop_three=0;

$auth_in_referral=0;
$auth_in_response=1;
$brute=1;

my $log_version="v2";
my $use_rcode=NOERROR();

sub OVERRIDE_WITH_SOA {return -1}

sub to_ip
{
	my $host=shift;
	if ($host eq "no")
	{
		return undef;
	}
	my $addr = gethostbyname($host);
	my ($a,$b,$c,$d) = unpack('C4',$addr);
	return "$a.$b.$c.$d";
}

my $my_ip=to_ip(hostname());
print "I am ".hostname()." with IP  $my_ip \n";

my $rf="report.txt";

my $ZONE="world"; 
my $DEBUG=2;
my $DUMPFILE="dumpfile.txt";
my $MODE;
my $ROLE="parent+victim+attacker";

my $IP_PARENT2;
my $IP_VICTIM2;
my $IP_ATTACKER2;
my $ZONE3="canary.security.lab.sit.cased.de";

GetOptions("ip_parent=s" => \$IP_PARENT2,
			"ip_victim=s" => \$IP_VICTIM2,
			"ip_attacker=s" => \$IP_ATTACKER2,
			"zone=s" => \$ZONE2,
			"debug=i" => \$DEBUG,
			"mode=s" => \$MODE,
			"dumpfile=s" => \$DUMPFILE,
			"role=s" => \$ROLE);

elsif ($MODE eq "sitprod")
{
	$IP_PARENT=$IP_PARENT2 || "141.12.174.19" ;
	$IP_VICTIM=$IP_VICTIM2 || "141.12.174.20" ;
	$IP_ATTACKER= $IP_ATTACKER2 || "141.12.174.21";
	$ZONE= $ZONE3 || "mundo";
}

print "parent IP = $IP_PARENT, victim IP = $IP_VICTIM, attacker IP = $IP_ATTACKER, zone=$ZONE, role=$ROLE\n";

$IP_PARENT=to_ip($IP_PARENT);
$IP_VICTIM=to_ip($IP_VICTIM);
$IP_ATTACKER=to_ip($IP_ATTACKER);

my @listen_ips;

my @role_list=split/\+/,$ROLE;
my $i;
for ($i=0;$i<scalar(@role_list);$i++)
{
	if ($role_list[$i] eq "parent")
	{
		if ($MODE=~/azure|sit/)
		{
			$cloud_parent=1;
		}
		print "In parent role: listening on $IP_PARENT\n";
		push @listen_ips,$IP_PARENT;
	}
	elsif ($role_list[$i] eq "victim")
	{
		print "In victim role: listening on $IP_VICTIM\n";
		push @listen_ips,$IP_VICTIM;
		if ($MODE=~/azure|sit/)
		{
			$cloud_victim=1;
		}
	}
	elsif ($role_list[$i] eq "attacker")
	{
		print "In attacker role: listening on $IP_ATTACKER\n";
		push @listen_ips,$IP_ATTACKER;
		if ($MODE=~/azure|sit/)
		{
			$cloud_attacker=1;
		}
	}
	else
	{
		die "Unknown role: $role_list[$i] (expecting parent|victim|attacker)\n";
	}
}

if ($MODE=~/azure/)
{
	print "Overriding listening list with the single local address: $my_ip\n";
	@listen_ips=($my_ip);
}


sub fplog
{
	return;
	
	my $type=shift;
	my $msg=shift;
	my $t=gmtime();
	$t=~tr/\r\n//;
	print $t." LOGTYPE: $type ".$msg."\r\n";
	$| = 1;
}

sub ip_to_int
{
	my $ip=shift;
	my ($a,$b,$c,$d)=split/\./,$ip;
	return ($a<<24)|($b<<16)|($c<<8)|$d;
}

	my %ip_for_bs=("victim_one"=>"0.0.1.1","victim_two"=>"0.0.1.2","victim_error"=>"0.0.1.4","attacker_one"=>"0.0.5.1","attacker_two"=>"0.0.5.2","attacker_three"=>"0.0.5.3","attacker_error"=>"0.0.5.4");
	#my %ip_for_bs=("victim_one"=>"0.0.1.1","victim_two"=>"0.0.1.2","victim_error"=>$IP_VICTIM,"attacker_one"=>"0.0.5.1","attacker_two"=>"0.0.5.2","attacker_three"=>"0.0.5.3","attacker_error"=>"0.0.5.4");
	#my %ip_for_bs=("victim_one"=>"1.1.1.1","victim_two"=>"1.2.2.2","victim_error"=>"1.4.4.4","attacker_one"=>"5.1.1.1","attacker_two"=>"5.2.2.2","attacker_three"=>"5.3.3.3","attacker_error"=>"5.4.4.4");
	#my %ip_for_bs=("victim_one"=>"127.0.0.1","victim_two"=>"127.0.0.1","victim_error"=>"127.0.0.1","attacker_one"=>"127.0.0.1","attacker_two"=>"127.0.0.1","attacker_three"=>"127.0.0.1","attacker_error"=>"127.0.0.1");
	my %mx_for_bs=("victim_one"=>$mx,"victim_two"=>$mx,"victim_error"=>$mx,"attacker_one"=>$mx,"attacker_two"=>$mx,"attacker_three"=>$mx,"attacker_error"=>$mx);
	my %txt_for_bs=("victim_one"=>$txt,"victim_two"=>$txt,"victim_error"=>$txt,"attacker_one"=>$txt,"attacker_two"=>$txt,"attacker_three"=>$txt,"attacker_error"=>$txt);


sub BS_response
{
	my $query_type=shift;
	my $BS_type=shift;
	my $rr;
	my $mx="vm26.lab.sit.cased.de";
	my $txt="debug";
	if ($query_type eq T_A())
	{
		return dns_answer(QPTR, T_A(), C_IN, 9999999, rr_A(ip_to_int($ip_for_bs{$BS_type})));
	}
	elsif ($query_type eq T_MX())
	{
		return dns_answer(QPTR, T_MX(), C_IN, 9999999, rr_MX(1,"mx-".$ip_for_bs{$BS_type}."-mx"));
	}
	elsif ($query_type eq T_TXT())
	{
		return dns_answer(QPTR, T_TXT(), C_IN, 9999999, rr_TXT("txt-".$ip_for_bs{$BS_type}."-txt"));
	}
	#elsif ($query_type eq T_TXT())
	#{
	#	# SPF...
	#	return dns_answer(QPTR, T_TXT(), C_IN, 9999999, rr_TXT("v=spf1 ip4:40.122.0.0/16 -all"));
	#}
	else
	{
		fplog("session","Oops - can't generate BS for type $Type2A{$query_type}\n");
		$use_rcode=OVERRIDE_WITH_SOA();
		#return dns_answer(QPTR, T_A(), C_IN, 9999999, rr_A(ip_to_int("9.9.9.9")));
	}
}


sub BS_response_short
{
	my $query_type=shift;
	my $BS_type=shift;
	my $rr;
	my $mx="vm26.lab.sit.cased.de";
	my $txt="debug";
	if ($query_type eq T_A())
	{
		return dns_answer(QPTR, T_A(), C_IN, 15, rr_A(ip_to_int($ip_for_bs{$BS_type})));
	}
	elsif ($query_type eq T_MX())
	{
		return dns_answer(QPTR, T_MX(), C_IN, 9999999, rr_MX(1,"mx-".$ip_for_bs{$BS_type}."-mx"));
	}
	elsif ($query_type eq T_TXT())
	{
		return dns_answer(QPTR, T_TXT(), C_IN, 9999999, rr_TXT("txt-".$ip_for_bs{$BS_type}."-txt"));
	}
	#elsif ($query_type eq T_TXT())
	#{
	#	# SPF...
	#	return dns_answer(QPTR, T_TXT(), C_IN, 9999999, rr_TXT("v=spf1 ip4:40.122.0.0/16 -all"));
	#}
	else
	{
		fplog("session","Oops - can't generate BS for type $Type2A{$query_type}\n");
		$use_rcode=OVERRIDE_WITH_SOA();
		#return dns_answer(QPTR, T_A(), C_IN, 9999999, rr_A(ip_to_int("9.9.9.9")));
	}
}


# Count referral caches
sub test_size
{
	my $head=shift;
	my $test=shift;
	my $sess=shift;
	my $tail=shift;
	my $dnsmsg=shift;

	if ($cloud_victim or ($dnsmsg->{query}{to} eq $IP_VICTIM))
	{
		if ($head=~/^one[0-9]{0,2}\.sz[0-9]{0,2}$/ or $head eq "sz")
		{
			$dnsmsg->{auth}.=dns_answer(dns_simple_dname("sz.$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.sz.$test.session-$sess.$tail"));
			$dnsmsg->{aucount}++;
			$dnsmsg->{add}.=dns_answer(dns_simple_dname("ns.sz.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($IP_ATTACKER)));
			$dnsmsg->{adcount}++;
			$dnsmsg->{aa}=0;
		}
		else
		{
			fplog("session","Unexpected query at victim: $head");
			$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"victim_error");
			$dnsmsg->{ancount}++;
			$dnsmsg->{aa}=0;

		}
	}	
	else
	{
		# Attacker
		if ($head=~/^one[0-9]{0,2}\.sz[0-9]{0,2}$/)
		{
			# that's expected since in phase 2 we sent a referrer to here...
			$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"attacker_two");
			$dnsmsg->{ancount}++;
			$dnsmsg->{aa}=1;
		}
		else
		{
			fplog("session","Unexpected query at attacker: $head");
			$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"attacker_error");
			$dnsmsg->{ancount}++;
			$dnsmsg->{aa}=1;

		}
		
	}
}



# Count answer caches
sub test_asize
{
	my $head=shift;
	my $test=shift;
	my $sess=shift;
	my $tail=shift;
	my $dnsmsg=shift;

	if ($cloud_victim or ($dnsmsg->{query}{to} eq $IP_VICTIM))
	{
		if ($head eq "one")
		{
			$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"victim_one");
			$dnsmsg->{ancount}++;
			$dnsmsg->{aa}=1;
		}
		else
		{
			fplog("session","Unexpected query at victim: $head");
			$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"victim_error");
			$dnsmsg->{ancount}++;
			$dnsmsg->{aa}=0;

		}
	}	
	else
	{
		# Attacker
		fplog("session","Unexpected query at attacker: $head");
		$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"attacker_error");
		$dnsmsg->{ancount}++;
		$dnsmsg->{aa}=1;
	}
}



sub handler
{
	my $domain=shift;
	my $residual=shift;
	my $type=shift;
	my $class=shift;
	my $dnsmsg=shift;
	my $from=shift;
	
	#print "In handler: domain=$domain, residual=$residual, type=$Type2A{$type}, class=$Class2A{$class}\n";
	open(FR,">>rawdns.txt");
	print FR "$log_version,$ROLE,".time().",$dnsmsg->{query}{from},$dnsmsg->{query}{from_port},$dnsmsg->{query}{to},$dnsmsg->{query}{qid},$residual\.$domain,$Class2A{$class},".(($Type2A{$type})||(sprintf("QType=0x%04x",$type)))."\n";
	my $old_fh = select(FR);
	$| = 1;
	select($old_fh);
	close(FR);
	
	my $query=$residual.".".$domain;

	if ($query=~/^(.*)(test[a-zA-Z0-9-]+)\.session-([a-zA-Z0-9-]+)\.(.*)$/)
	{
		my $head=$1;
		if (substr($head,-1) eq ".")
		{
			$head=substr($head,0,-1);
		}
		my $test=$2;
		my $sess=$3;
		my $tail=$4;
		
		my $auth=0; # This is a referral, so non-auth
		if ($test=~/auth/)
		{
			$auth=1;
		}
			
		if ($type eq T_MX())
		{
			$dnsmsg->{answer}.=dns_answer(QPTR(), T_MX(), C_IN, 9999999, rr_MX(1,$query));
			$dnsmsg->{ancount}++;
			return;
		}
		if  (($type eq T_TXT()) and ($head=~/^_dmarc/))
		{
			$dnsmsg->{rcode}=NXDOMAIN();
			return;
		}

		if ($cloud_parent or ($dnsmsg->{query}{to} eq $IP_PARENT))
		{
			my $ip=$IP_VICTIM;
			
			if ($test=~/magic/)
			{
				$ip=$IP_ATTACKER;
			}
			
			$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
			$dnsmsg->{aucount}++;
			$dnsmsg->{add}.=dns_answer(dns_simple_dname("ns.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
			$dnsmsg->{adcount}++;
			$dnsmsg->{aa}=($auth and $auth_in_referral);  
			
			return;
		}
		
		my $ref=$test;
		$ref=~tr/-/_/;
		if ($ref=~/(.*)_magic/)
		{
			$ref=$1;
		}
		if ($ref=~/test_q_([0-9]{0,2})/)
		{
			$ref="test_q";
		}
		
		if ($cloud_victim or ($dnsmsg->{query}{to} eq $IP_VICTIM))
		{
			my $ip=$IP_VICTIM;
			if ($test=~/magic/)
			{
				#$dnsmsg->{auth}.=dns_answer(dns_simple_dname("session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("ns.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				#$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				$dnsmsg->{rcode}=REFUSED();
				return;
			}
			if ($test=~/-cnm$/)
			{
				$dnsmsg->{answer}.=dns_answer(QPTR(), T_CNAME(), C_IN, 9999999, rr_CNAME("$head.".substr($test,0,-4).".session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			if ($test=~/-cnms$/)
			{
				$dnsmsg->{answer}.=dns_answer(QPTR(), T_CNAME(), C_IN, 9999999, rr_CNAME("one.".substr($test,0,-5).".session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			if ($test=~/-cnmn$/)
			{
				$dnsmsg->{answer}.=dns_answer(QPTR(), T_CNAME(), C_IN, 9999999, rr_CNAME("ns2.".substr($test,0,-5).".session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_NS()) and ($head eq ""))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{add}.=dns_answer(dns_simple_dname("ns.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{adcount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_NS()) and ($head=~/^one[0-9]{0,2}|ns$/))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("ns.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_A()) and ($head eq "ns"))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("ns.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{ancount}++;
				if ($auth and $auth_in_response)
				{
					$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
					$dnsmsg->{aucount}++;
				}
				$dnsmsg->{aa}=1;
				return;
			}
			elsif ($brute and ($type eq T_A()) and ($head eq "ns2") and ($test=~/test-ns0/))   # Ugly kludge for BIND...
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("ns2.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{ancount}++;
				if ($auth and $auth_in_response)
				{
					$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
					$dnsmsg->{aucount}++;
				}
				$dnsmsg->{aa}=1;
				return;
			}
			elsif ((($type eq T_AAAA()) or ($type eq T_A6())) and ($head eq "ns"))
			{
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("$head.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif ((($type eq T_AAAA()) or ($type eq T_A6())) and ($head=~/^ns[xy][0-9]{0,2}$/))
			{
				# special treatment for the QID test
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("$head.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_AAAA()) and ($head eq "ns2"))
			{
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("ns.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				$dnsmsg->{rcode}=NXDOMAIN();
				return;
			}
			elsif (($type eq T_A()) and ($head eq "empty"))
			{
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_A()) and ($test=~/^test-good/))
			{
				$dnsmsg->{answer}.=BS_response($dnsmsg->{query}{qtype},"victim_one");
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;  
				return;
			}
			elsif ((not ($head=~/^(one|one[0-9]{0,2}\.sub|one[0-9]{0,2}\.sz|sz|two[0-9]{0,2}|two[0-9]{0,2}\.sub|x\.y|ns\.sub|two[0-9]{0,2}\.ns)[0-9]{0,2}|ns[xy][0-9]{0,2}|zwei\.one[0-9]{0,2}|zwei[0-9]{0,2}$/)) and (not (($head eq "ns2") and (($test eq "test-ns") or ($test eq "test-ns-auth")))))
			{
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("ns.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				$dnsmsg->{rcode}=NXDOMAIN();
				return;
			}

		}
				
		if ($cloud_attacker or ($dnsmsg->{query}{to} eq $IP_ATTACKER))
		{
			my $ip=$IP_ATTACKER;
			if (($type eq T_NS()) and ($head eq ""))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.$test.session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{add}.=dns_answer(dns_simple_dname("ns.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{adcount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_A()) and ($head eq "ns"))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("ns.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_A()) and ($head eq "ns.sz"))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("ns.sz.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{ancount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif (($type eq T_NS()) and ($head=~/^sz$/))
			{
				$dnsmsg->{answer}.=dns_answer(dns_simple_dname("sz.$test.session-$sess.$tail"), T_NS(), C_IN, 9999999, rr_NS("ns.sz.$test.session-$sess.$tail"));
				$dnsmsg->{ancount}++;
				$dnsmsg->{add}.=dns_answer(dns_simple_dname("ns.sz.$test.session-$sess.$tail"), T_A(), C_IN, 9999999, rr_A(ip_to_int($ip)));
				$dnsmsg->{adcount}++;
				$dnsmsg->{aa}=1;
				return;
			}
			elsif ((($type eq T_AAAA()) or ($type eq T_A6())) and (($head eq "ns") or ($head eq "ns2")))
			{
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("$head.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				$dnsmsg->{aa}=1;
				return;
			}


		}
				
		if (defined &$ref)
		{
			if  ($random_drop_one and ($cloud_victim or ($dnsmsg->{query}{to} eq $IP_VICTIM)) and ($head=~/one/) and (not ($test=~/test-size|ttt1|ttt1-auth|test-ns-a|test-x-ns-a/)) and (rand()<0.5))
			{
				$dnsmsg->{rcode}=DROP();
				return;
			}
			if  ($random_drop_two and ($cloud_victim or ($dnsmsg->{query}{to} eq $IP_VICTIM)) and ($head=~/^two|^ns2/) and (not ($test=~/test-size|ttt1|ttt1-auth|test-ns-a|test-x-ns-a/)) and (rand()<0.5))
			{
				$dnsmsg->{rcode}=DROP();
				return;
			}
			if  ($random_drop_three and ($cloud_attacker or ($dnsmsg->{query}{to} eq $IP_ATTACKER)) and ($head=~/three/) and (not ($test=~/test-size|ttt1|ttt1-auth|test-ns-a|test-x-ns-a/)) and (rand()<0.5))
			{
				$dnsmsg->{rcode}=DROP();
				return;
			}
			&$ref($head,$test,$sess,$tail,$dnsmsg);

			#print " *** head=$head, type=$type, use_rcode=$use_rcode\n";
			if ($use_rcode ne NOERROR())
			{
				$dnsmsg->{answer}="";
				$dnsmsg->{auth}="";
				$dnsmsg->{add}="";
				$dnsmsg->{ancount}=0;
				$dnsmsg->{aucount}=0;
				$dnsmsg->{adcount}=0;
				$dnsmsg->{auth}.=dns_answer(dns_simple_dname("$head.$test.session-$sess.$tail"), T_SOA(), C_IN, 9999999, rr_SOA("ns.$test.session-$sess.$tail","admin.$test.session-$sess.$tail",12345,9999999,9999999,9999999,9999999));
				$dnsmsg->{aucount}++;
				if ($use_rcode eq OVERRIDE_WITH_SOA())
				{
					$dnsmsg->{rcode}=NOERROR();
				}
				else
				{
					$dnsmsg->{rcode}=$use_rcode;
				}
				$use_rcode=NOERROR();
			}
		}
		else
		{
			print "oops - what kind of test is this? $test ($head $sess $tail)\n";
		}
		return;
	}
	
	return;
}

sub mylog
{
	my $err=shift;
	open(FR,">>rawdns.txt");
	print FR "$log_version,$ROLE,".time().",ERROR: $err\n";
	my $old_fh = select(FR);
	$| = 1;
	select($old_fh);
	close(FR);
}

$ns = new Stanford_DNSserver(listen_on => \@listen_ips, debug => $DEBUG, daemon => "no", logfunc => \&mylog);
$ns->add_dynamic($ZONE, \&handler);
$ns->answer_queries();