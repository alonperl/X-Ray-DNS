$DBG_LINE="";
$DBG_TEST="test_w11bis";
use POSIX;
#use Graph::Undirected;
#my $g = Graph::Undirected->new; # An undirected graph.

my $part="";
if ($ARGV[0]=~/rawdns_laius_(.*)\.txt/)
{
	$part=$1;
}
$PR=$ARGV[3];

$omit_doubles=1;
$include_delayed=$ARGV[4];
$use_version=$ARGV[5];
$oneless=0;

$ttl=15;
$dt=5;

$port_bucket_size=1;

$count_goodbad_as_good=1;
$count_goodbad_as_bad=1;

$use_first=1;

$N_first_hits=10;

$brute=1;

$detect_pdns=not $brute;

$skip_A_tests=$ARGV[6];   # set =1 in SMTP (only)

$new_geo=1;

#$mode_str="omit_doubles=$omit_doubles; include delayed tests=$include_delayed; show bind.version=$use_version; allow tests without 'one'=$oneless; TTL for short lived records=$ttl; time margin=$dt; port bucket size=$port_bucket_size; count good+bad as good=$count_goodbad_as_good; count good+bad as bad=$count_goodbad_as_bad; use only first check=$use_first; use first N hits=$N_first_hits";

my %success_name=(1 => "S", 0 => "F", "U" => "A");

my %ver;
if ($use_version)
{
	open(FV,"versions.txt") or die "Can't open versions.txt";
	while($line=<FV>)
	{
		chomp $line;
		($ln,$ip,$version)=split/,/,$line;
		$ver{$ln}=$version;
	}
	close(FV);
}

sub ip_to_int
{
	my $ip=shift;
	my ($a,$b,$c,$d)=split/\./,$ip;
	return ($a<<24)|($b<<16)|($c<<8)|$d;
}


sub hamming
{
	my $x=shift;
	my $y=shift;
	my $result=0;
	while (($x ne 0) or ($y ne 0))
	{
		$result+=($x^$y)&1;
		$x>>=1;
		$y>>=1;
	}
	return $result;
}


my %ip_to_country;

if ($new_geo)
{
	open(FH,"/etc/webserver/data/rawdnsfiles/ip2isp.csv") or die "Can't open ip2isp.csv";
	$geoln=0;
	while($line=<FH>)
	{
		chomp $line;
		if ($line=~/^"([0-9]+)";"([0-9]+)";"([A-Z]{2})";"(.*)";(.*)$/)
		{
			$from[$geoln]=$1;
			$to[$geoln]=$2;
			$ip_to_country{$1}=$3;
			$maybe_isp=$5;
			my $isp="(unavailable)";
			if ($maybe_isp=~/"(.*)"/)
			{
				$isp=$1;
			}
			$asn_isp[$geoln]="AS(unavailable) $isp";
			$class_b[$geoln]="(unavaiable)";
			$geoln++;
		}
		else
		{
			print "ERROR in ip2isp.csv: cant parse line <$line>\n";
			die;
		}
	}
	close(FH);
}
else
{
	open(FH,"ip2nation.csv") or die "Can't open file ip2nation.csv";
	while($line=<FH>)
	{
		chomp $line;
		($ip,$cn)=split/,/,$line;
		$ip_to_country{$ip}=$cn;
	}
	close(FH);

	open(FH,"geo_isp3.csv") or die "Can't open file geo_isp3.csv";
	$geoln=0;
	while($line=<FH>)
	{
		chomp $line;
		($from[$geoln],$to[$geoln],$asn_isp[$geoln],$class_b[$geoln])=split/\|/,$line;
		#($asn[$geoln],$isp[$geoln])=split/ /,$asn_isp[$geoln],2;
		$geoln++;
	}
	close(FH);
}

my @ip_list=sort {$a<=>$b} (keys %ip_to_country);

sub get_country
{
	my $ip=ip_to_int(shift);
	my $first=0;
	my $last=scalar(@ip_list)-1;
	
	while(1)
	{
		
		$mid=int(($first+$last)/2);
		if ($mid==$first)
		{
			return $ip_to_country{$ip_list[$mid]};
		}
		if ($ip<$ip_list[$mid])
		{
			$last=$mid;
		}
		elsif ($ip==$ip_list[$mid])
		{
			return $ip_to_country{$ip_list[$mid]};
		}
		else
		{
			$first=$mid;
		}
	}
}

sub num_to_ip
{
	my $num=shift;
	return (($num>>24)&0xFF).".".(($num>>16)&0xFF).".".(($num>>8)&0xFF).".".($num&0xFF);
}

sub isp_for_ip
{
	my $ip=shift;
	my ($a,$b,$c,$d)=split/\./,$ip;
	my $num=($a<<24)|($b<<16)|($c<<8)|$d;

	my $first=0;
	my $last=$geoln-1;
	while ($first<$last)
	{
		my $mid=int(($last+$first)/2);
		if (($from[$mid]<=$num) && ($from[$mid+1]>$num))
		{
			# one last check...
			if ($num<=$to[$mid])
			{
				return num_to_ip($from[$mid])."-".num_to_ip($to[$mid])." ".$asn_isp[$mid];
				#return "block-".$mid." ".$asn_isp[$mid];
			}
			else
			{
				return undef;
			}
		}
		elsif ($from[$mid]>$num)
		{
			$last=$mid;
		}
		else
		{
			$first=$mid+1;
		}
	}
	
	# XXXXX
	return undef;
	die "**** DYING\n**** DYING\n**** DYING\n**** DYING\n**** DYING\n**** DYING\n**** DYING\nHuh? ip=<$ip>, num=$num first=$first last=$last\n";
}



#my %server_sig=("old_BIND"=>0x07f, "new_BIND"=>0x079, "Unbound"=>0xf7e, "MaraDNS"=>0x000, "PowerDNS" => 0xffe);
#my %server_sig=("old_BIND"=>0x228f, "new_BIND"=>0x228d, "Unbound"=>0x20ee, "Unbound_Hardened"=>0x3c00, "MaraDNS"=>0x0000, "Microsoft DNS 6.x" => 0x23fe);
#my %server_sig=("new_BIND"=>0x450d, "old_BIND"=>0x450f, "BIND 9.8.2rc1 modified by RedHat"=>0x4101, "Unbound"=>0x41ee, "hardened DNS server"=>0x7800, "MaraDNS"=>0x0000, "Microsoft DNS 6.0" => 0x47fe, "Microsoft DNS 6.1" => 0x47de);
#my %server_sig=("* new_BIND"=>0x22879, "* old_BIND"=>0x2287f, "BIND 9.8.2rc1 modified by RedHat"=>0x20801, "* Unbound"=>0x20f7e, "* hardened DNS server"=>0x3c000, "* MaraDNS"=>0x00000, "Microsoft DNS 6.0" => 0x23ffe, "Microsoft DNS 6.1" => 0x23eaa, "ancient BIND 9" => 0x2007f);
%server_sig=(
	"! New BIND 9.x"=>0x3e2879, 
	"! Old BIND 9.x"=>0x3e287f, 
	"! New BIND 9.x with DNSSEC-validation"=> 0x360801, 
	"* Ancient BIND 9.x" => 0x3e007f, 
	"! Unbound"=> 0x320f7e, 
	"! Hardened DNS server"=> 0x03c000, 
	"! PowerDNS" => 0x3a3ffe, 
	"! MaraDNS" => 0x300000, 
	"* Microsoft DNS 6.0" => 0x3a3ffe, 
	"! Microsoft DNS 6.1" => 0x3a3eaa, 
	"! Microsoft DNS 6.2 and above" => 0x3e3eab, 
	"! Non-DNAME resolver forwarding to Google public DNS" => 0x3a0000, 
	"! DNAME-enabled resolver forwarding to Google public DNS" => 0x3e0001, 
	"! OpenDNS public DNS" => 0x3a3aaa,
	"! Nominum Vantio CacheServe" => 0x300000,
	"* New BIND 9.x with DNSSEC-validation and A-fetch"=> 0x368801, 
	
	#"? Microsoft DNS 6.0?? forwarding to OpenDNS public DNS" => 0x3a3afe, 
	#"? MS-DNS thingy2" => 0x3a122a, 
	#"? New BIND variant (without DNAME)" => 0x3a2878, 
	#"? Old BIND variant (without DNAME)" => 0x3a287e
);
sub parse_line
{
	my $line=shift;
	my $log_version;
	my $role;
	my $t;
	my $name;
	my $out_ip;
	my $out_port;
	my $ip_to;
	my $qid;
	my $class;
	my $type;
	
	chomp $line;
	if ((split/,/,$line)[0] eq "v2")
	{
		($log_version,$role,$t,$out_ip,$out_port,$ip_to,$qid,$name,$class,$type)=split/,/,$line;
	}
	else
	{
		($role,$t,$out_ip,$ip_to,$name,$class,$type)=split/,/,$line;
	}
	
	if ($name=~/test-good/)
	{
		next;
	}

	#next if ($out_ip=~/^54\./);
	
	my $head;
	my $test;
	my $prefix;
	my $ln;
	my $in_ip;
	my $bt;
	my $session_t;
	my $tail;
	if ($name=~/^(.*)(test-[a-z0-9-]*)\.session\-([0-9a-z]+)\-ln([0-9a-z]*)\-ip\-([0-9]+\-[0-9]+\-[0-9]+\-[0-9]+)\-bt([0-9]+)\-([0-9]+)\.(.*)$/)
	{
		$head=$1;
		if (substr($head,-1) eq ".")
		{
			$head=substr($head,0,-1);
		}
		$test=$2;
		$prefix=$3;
		$ln=$4;
		#$ln=(($ln-1) % 3) +1;
		$in_ip=$5;
		$bt=$6;
		if ($brute and ($ln=~/^[0-9]*$/))
		{
			$ln.=(($bt==0)?"b":"s");
		}
		
		$session_t=$7;
		$tail=$8;
		$in_ip=~tr/\-/\./;
		if ($test=~/\-magic$/)
		{
			$test=substr($test,0,-6);
		}
		#print "head=$head, test=$test, ln=$ln, in_ip=$in_ip (out_ip=$out_ip), bt=$bt, session_t=$session_t, tail=$tail\n";
		return ($t,$head,$test,$prefix,$ln,$in_ip,$out_ip,$bt,$name,$type,$out_port,$qid);
	}
}

my %origin_ip;

open(FH0,"$ARGV[0]") or die "Can't open $ARGV[0]";

while($line=<FH0>)
{
	#print STDERR $line;
	($t,$head,$test,$prefix,$ln,$in_ip,$out_ip,$bt,$name,$type,$out_port,$qid)=parse_line($line);
	#print "t=$t, test=$test, prefix=$prefix\n";

	next unless ($prefix eq $PR);
	
	$ever_seen{$ln}++;
	
	next unless (($type eq "A") or ($type eq "AAAA") or ($type eq "NS") or ($type eq "TXT"));
	
	next if ($name=~/magic/);
	
	next if  ($skip_A_tests and ($test=~/^(test-ns|test-ns-auth|test-w7|test-w8)$/));
	
	#$logic{"$ln $out_ip $test $bt"}{parent}.="<$head>";
	$logic{"$ln [MERGED] $test $bt"}{parent}.="<$head>";
	#$logic_time{"$ln $out_ip $test $bt"}{parent}.="<$head:$t>";
	$logic_time{"$ln [MERGED] $test $bt"}{parent}.="<$head:$t>";

	$origin_ip{$ln}=$in_ip;
	if ((not defined $in_ip) or ($in_ip eq ""))
	{
		die "Whoa - line=$line, and I have a problem with in_ip\n";
	}
	$ip_list{$ln}{$out_ip}++;
	($block_,$asn_,$isp_)=split/ /,isp_for_ip($out_ip),3;
	$isp_list{$ln}{$isp_}++;
	$asn_list{$ln}{$asn_}++;
	$country_list{$ln}{get_country($out_ip)}++;

}
close(FH0);

print STDERR "\n".localtime()." - Done with $ARGV[0]\n";

open(FH1,"$ARGV[1]") or die "Can't open $ARGV[1]";
my %visit;
my %perip;
my %bt_ct;
my %count_bt;
my %count_bt_total;



while($line=<FH1>)
{
	($t,$head,$test,$prefix,$ln,$in_ip,$out_ip,$bt,$name,$type,$out_port,$qid)=parse_line($line);
	#print "t=$t, test=$test, prefix=$prefix\n";
	
	if  (($prefix eq $PR) and ($test=~/test-qid-ns/) and ($head=~/^(ns[xy])([0-9]{0,2})$/))
	{
		$qid_ns_stat{$ln}{"$bt-$2"}{$1}{$type}=$qid;
		$port_ns_stat{$ln}{"$bt-$2"}{$1}{$type}=$out_port;
		
	}
	
	next unless (($prefix eq $PR) and (($type eq "A") or ($type eq "AAAA") or ($type eq "NS") or ($type eq "TXT")));
	
	next if  ($skip_A_tests and ($test=~/^(test-ns|test-ns-auth|test-w7|test-w8)$/));

	$name_seen{$ln}{$name}++;
	
	$ip_list{$ln}{$out_ip}++;
	($block_,$asn_,$isp_)=split/ /,isp_for_ip($out_ip),3;
	$isp_list{$ln}{$isp_}++;
	$asn_list{$ln}{$asn_}++;
	$country_list{$ln}{get_country($out_ip)}++;
	
	$count_t{$ln}++;
	if (defined $last_ip{$ln})
	{
		if ($out_ip ne $last_ip{$ln})
		{
			$flip_ip{$ln}++;
		}
	}
	$last_ip{$ln}=$out_ip;

	
	$country{$ln}=get_country($in_ip);
	
	$port_stat{$ln}{$out_port}++;

	$btct{$ln}{$bt}++;
	if (($test eq "test-size") and ($head=~/one[0-9]{0,2}\.sz/) and (($type eq "A") or ($type eq "TXT")))
	{
		$cache_count{$ln}{$bt}{$head}++;
	}
	
	if (($test eq "test-asize") and ($head eq "one") and (($type eq "A") or ($type eq "TXT")))
	{
		$acache_count{$ln}{$bt}++;
	}

	if ($test eq "test-ns-a")
	{
		#$ns{"$ln $out_ip $bt"}.="<found>";
		$ns{"$ln [MERGED] $bt"}.="<found>";
		#$a{"$ln $out_ip $bt"}.="<found>";
		$a{"$ln [MERGED] $bt"}.="<found>";
		if ($type eq "NS")
		{
			#$ns{"$ln $out_ip $bt"}.="<NS>";
			$ns{"$ln [MERGED] $bt"}.="<NS>";
		}
		if (($head eq "ns") and ($type eq "A" ))
		{
			#$a{"$ln $out_ip $bt"}.="<A-ns>";
			$a{"$ln [MERGED] $bt"}.="<A-ns>";
		}
	}
	if ($test eq "test-x-ns-a")
	{
		#$x_ns{"$ln $out_ip $bt"}.="<found>";
		$x_ns{"$ln [MERGED] $bt"}.="<found>";
		if ($type eq "NS")
		{
			#$x_ns{"$ln $out_ip $bt"}.="<NS>";
			$x_ns{"$ln [MERGED] $bt"}.="<NS>";
		}
	}
	
	if (0)
	{
	($block_,$asn_,$isp_)=split/ /,isp_for_ip($out_ip),3;
	$isp{$ln}{$isp_}++;
	$asn{$ln}{$asn_}++;
	$block{$ln}{$block_." ($isp_)"}++;
	$single_ip{$ln}{$out_ip}++;
	
	$g->add_vertex($out_ip);
	if (not defined $first_ip{$ln})
	{
		$first_ip{$ln}=$out_ip;
	}
	else
	{
		$g->add_edge($first_ip{$ln},$out_ip);
	}
		
	$class_c{$ln}{num_to_ip(ip_to_int($out_ip)&0xFFFFFF00)."/24"}++;
	}
	#if (not defined $isp{$ln})
	#{
	#	$isp{$ln}=isp_for_ip($out_ip);
	#}
	#else
	#{
	#	if ($isp{$ln} ne isp_for_ip($out_ip))
	#	{
	#		print "Oops123: at line $ln, already have ISP $isp{$ln} and now I have ".isp_for_ip($out_ip)." ($out_ip)\n";
	#	}
	#}
	
	$count_bt_total{$bt}++;
	$count_type{$type}++;
	
	$dom_any{$ln}{"$test,$prefix,$bt"}++;
	if ($type eq "NS")
	{
		$dom_NS{$ln}{"$test,$prefix,$bt"}++;
		$count_NS{$ln}++;
		if (not defined $ip_NS{$ln})
		{
			$ip_NS{$ln}=$out_ip;
		}
		elsif ($ip_NS{$ln} ne $out_ip)
		{
			#print "Ahem!!! got one: at $ln, had $ip_NS{$ln} but now $out_ip\n";
		}
		#print $line;
	}
	if ($head eq "ns")
	{
		$count_nsA{$ln}++;
		if (($type eq "AAAA") or ($type eq "A6"))
		{
			$count_nsAAAA{$ln}++;
		}
		else
		{
			#print "$ln,$name,$type\n";
			$count_ns_no_AAAA{$ln}++;
		}
	}
	#$logic{"$ln $out_ip $test $bt"}{victim}.="<$head>";
	$logic{"$ln [MERGED] $test $bt"}{victim}.="<$head>";
	#$logic_time{"$ln $out_ip $test $bt"}{victim}.="<$head:$t>";
	$logic_time{"$ln [MERGED] $test $bt"}{victim}.="<$head:$t>";
	if (not defined $first_encounter{$ln})
	{
		$first_encounter{$ln}=$t;
	}
	if ($head=~/two[0-9]{0,2}|ns2[0-9]{0,2}|two[0-9]{0,2}\.sub[0-9]{0,2}/)
	{
		$count_bt{$ln}{$test.",",$bt}=1;
	}
}
close(FH1);

print STDERR "\n".localtime()." - Done with $ARGV[1]\n";


foreach $ln (keys %acache_count)
{
	my $max_size=0;
	my %pop;
	foreach $bt (keys %{$acache_count{$ln}})
	{
		my $cur_sz=$acache_count{$ln}{$bt};
		$dbg.="$cur_sz,";
		if ($cur_sz>$max_size)
		{
			$max_size=$cur_sz;
		}
		$pop{$cur_sz}++;
	}
	$acache{$ln}=$max_size;
	my $max_pop=0;
	foreach $v (keys %pop)
	{
		if ($pop{$v}>$max_pop)
		{
			$max_pop=$pop{$v};
			$acache_maxpop{$ln}=$v;
		}
		#$cache_maxpop{$ln}.="$v|$pop{$v};"
	}
}

print STDERR "\n".localtime()." - Done with counting caches\n";

if (0)
{
	print "ISP per line\n";
	foreach $v (keys %isp)
	{
		print "$v,".scalar(keys %{$isp{$v}}).",";
		$s="";
		foreach $u (sort keys %{$isp{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_isp{$s}++;
	}
	print "\n\n\n";
	print "ISP distribution\n";
	foreach $g (sort {$pop_isp{$b}<=>$pop_isp{$a}} keys %pop_isp)
	{
		print "$g $pop_isp{$g}\n";
	}
	
	print "\n\n\n";
	print "ASN per line\n";
	
	foreach $v (keys %asn)
	{
		print "$v,".scalar(keys %{$asn{$v}}).",";
		$s="";
		foreach $u (sort keys %{$asn{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_asn{$s}++;
	}
	print "\n\n\n";
	print "ASN distribution\n";
	
	foreach $g (sort {$pop_asn{$b}<=>$pop_asn{$a}} keys %pop_asn)
	{
		print "$g $pop_asn{$g}\n";
	}
	print "\n\n\n";
	
	print "IP-block per line\n";
	
	foreach $v (keys %block)
	{
		print "$v,".scalar(keys %{$block{$v}}).",";
		$s="";
		foreach $u (sort keys %{$block{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_block{$s}++;
	}
	print "\n\n\n";
	print "IP-block distribution\n";
	
	foreach $g (sort {$pop_block{$b}<=>$pop_block{$a}} keys %pop_block)
	{
		print "$g $pop_block{$g}\n";
	}
	print "\n\n\n";
	
	print "Class-C per line\n";
	
	foreach $v (keys %class_c)
	{
		print "$v,".scalar(keys %{$class_c{$v}}).",";
		$s="";
		foreach $u (sort keys %{$class_c{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_class_c{$s}++;
	}
	print "\n\n\n";
	print "Single IP per line\n";
	
	foreach $v (keys %single_ip)
	{
		print "$v,".scalar(keys %{$single_ip{$v}}).",";
		$s="";
		foreach $u (sort keys %{$single_ip{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_single_ip{$s}++;
	}
	print "\n\n\n";
	print "Single IP distribution\n";
	
	foreach $g (sort {$pop_single_ip{$b}<=>$pop_single_ip{$a}} keys %pop_single_ip)
	{
		print "$g $pop_single_ip{$g}\n";
	}
	print "\n\n\n";
	
	print "Class-C per line\n";
	
	foreach $v (keys %class_c)
	{
		print "$v,".scalar(keys %{$class_c{$v}}).",";
		$s="";
		foreach $u (sort keys %{$class_c{$v}})
		{
			$s.="$u"."|";
		}
		chop $s;
		print "$s\n";
		$pop_class_c{$s}++;
	}
	print "\n\n\n";
	print "Class-C distribution\n";
	
	foreach $g (sort {$pop_class_c{$b}<=>$pop_class_c{$a}} keys %pop_class_c)
	{
		print "$g $pop_class_c{$g}\n";
	}
	print "\n\n\n";
	
	print "Connectivity graph analysis\n";
	$c=0;
	foreach $a ($g->connected_components())
	{
		print "Component $c:\n";
		foreach $b (@{$a})
		{
			print "$c $b ".isp_for_ip($b)."\n";
		}
		$c++;
	}
	
	foreach $ty (keys %count_type)
	{
		print "$ty,$count_type{$ty}\n";
	}
	print "\n\n\n";
	print "Unique lines with NS: ".scalar(keys %count_NS)."\n";
	foreach $k (keys %count_NS)
	{
		print "$k,$count_NS{$k}\n";
	}
	
	$n_any=0;
	$n_NS=0;
	$n_oops=0;
	foreach $x (keys %dom_any)
	{
		$n_any++;
		print "$x NS portion: ".scalar(keys %{$dom_NS{$x}})."/".scalar(keys %{$dom_any{$x}})."\n";
		if (scalar(keys %{$dom_NS{$x}})>0)
		{
			$n_NS++;
		}
		if ((scalar(keys %{$dom_NS{$x}})>0) and (scalar(keys %{$dom_NS{$x}}) ne scalar(keys %{$dom_any{$x}})))
		{
			$n_oops++;
		}
	}
	
	print "Total unique: $n_any, total unique NS: $n_NS, ratio: ".($n_NS/$n_any)."  oops: $n_oops\n";
	
	foreach $y (keys %ip_NS)
	{
		$ip_ctr{$ip_NS{$y}}++;
	}
	
	foreach $z (keys %ip_ctr)
	{
		print "IP with NS: $z - count $ip_ctr{$z}\n";
	}
	
	#exit;
	
	print "Unique lines with ns: ".scalar(keys %count_nsA)."\n";
	foreach $k (keys %count_nsA)
	{
		print "$k,$count_nsA{$k}\n";
	}
	print "Unique lines with ns (AAAA or A6): ".scalar(keys %count_nsAAAA)."\n";
	foreach $k (keys %count_nsAAAA)
	{
		print "$k,$count_nsAAAA{$k}\n";
	}
	print "Unique lines with ns (not AAAA nor A6): ".scalar(keys %count_ns_no_AAAA)."\n";
	foreach $k (keys %count_ns_no_AAAA)
	{
		print "$k,$count_ns_no_AAAA{$k}\n";
	}
	#exit;
}

open(FH2,"$ARGV[2]") or die "Can't open $ARGV[2]";
my %policy;
#foreach $k (keys %visit)
#{
#	$policy{$k}=();
#}

my %testbit=(
	"test-dname" => 0,
	"test-ns0" => 1,
	"test-ns0-auth" => 2,
	"test-ns" => 3,
	"test-ns-auth" => 4,
	"test-ns2" => 5,
	"test-ns2-auth" => 6,
	"test-b4" => 7,
	"test-u1-auth" => 8,
	#"test-u1bis-auth" => ,
	"test-u3-2" => 9,
	"test-u3-3" => 10,
	"test-u3-4" => 11);
	
while($line=<FH2>)
{
	($t,$head,$test,$prefix,$ln,$in_ip,$out_ip,$bt,$name,$type,$out_port,$qid)=parse_line($line);
	#print "t=$t, test=$test, prefix=$prefix\n";

	next unless ($prefix eq $PR);
	next if  ($skip_A_tests and ($test=~/^(test-ns|test-ns-auth|test-w7|test-w8)$/));

	$name_seen{$ln}{$name}++;

	if (($test eq "test-size") and ($head=~/one[0-9]{0,2}\.sz/) and (($type eq "A") or ($type eq "TXT")))
	{
		$cache_count_valid{$ln}{$bt}{$head}++;
	}

	if  (($test=~/test-ns2/) and ($head eq "ns2"))
	{
		$qid_stat{$ln}{"$test $bt"}{$type}=$qid;
		$xport_stat{$ln}{"$test $bt"}{$type}=$out_port;
	}
	if  (($test eq "test-q") and ($head =~ /nsz[0-9]{0,2}/))
	{
		$head =~ /nsz([0-9]{0,2})/;
		$qid_stat{$ln}{"$test-$1 $bt"}{$type}=$qid;
		$xport_stat{$ln}{"$test-$1 $bt"}{$type}=$out_port;
	}
	$port_stat{$ln}{$out_port}++;
	
	if  (($test eq "test-x-ns-a") )
	{
		#$x_a{"$ln $out_ip $bt"}.="<found>";
		$x_a{"$ln [MERGED] $bt"}.="<found>";

		if (($type eq "AAAA" ) and ($head eq "ns2"))
		{
			#$x_a{"$ln $out_ip $bt"}.="<AAAA-ns>";
			$x_a{"$ln [MERGED] $bt"}.="<AAAA-ns>";
		}
	}

	next unless (($type eq "A") or ($type eq "AAAA") or ($type eq "NS") or ($type eq "TXT"));
	$ip_list{$ln}{$out_ip}++;
	($block_,$asn_,$isp_)=split/ /,isp_for_ip($out_ip),3;
	$isp_list{$ln}{$isp_}++;
	$asn_list{$ln}{$asn_}++;
	$country_list{$ln}{get_country($out_ip)}++;

	if (($test eq "test-size") and ($head=~/one[0-9]{0,2}\.sz/))
	{
		$cache_count2{$ln}{$bt}{$head}++;
		#print "At line $ln, adding to cache_count2: $ln $bt $head ($name)\n";
		#print "Original line: $line\n";
	}

	if (($test eq "test-x-ns-a") and ($head eq "ns2"))
	{
		if ($type eq "A" )
		{
			#$x_a{"$ln $out_ip $bt"}.="<A-ns>";
			$x_a{"$ln [MERGED] $bt"}.="<A-ns>";
		}
	}
	#$logic{"$ln $out_ip $test $bt"}{attacker}.="<$head>";
	$logic{"$ln [MERGED] $test $bt"}{attacker}.="<$head>";
	#$logic_time{"$ln $out_ip $test $bt"}{attacker}.="<$head:$t>";
	$logic_time{"$ln [MERGED] $test $bt"}{attacker}.="<$head:$t>";
	
}
close(FH2);

print STDERR "\n".localtime()." - Done with $ARGV[2]\n";

foreach $ln (keys %cache_count)
{
	my $max_size=0;
	my %pop;
	foreach $bt (keys %{$cache_count{$ln}})
	{
		my $cur_sz=0;
		foreach $k (keys %{$cache_count{$ln}{$bt}})
		{
			#if ($cache_count_valid{$ln}{$bt}{$k})
			{
				$cur_sz++;
			}
		}
		#$dbg.="$cur_sz,";
		if ($cur_sz>$max_size)
		{
			$max_size=$cur_sz;
		}
		$pop{$cur_sz}++;
	}
	$cache{$ln}=$max_size;
	my $max_pop=0;
	foreach $v (keys %pop)
	{
		if ($pop{$v}>$max_pop)
		{
			$max_pop=$pop{$v};
			$cache_maxpop{$ln}=$v;
		}
		#$cache_maxpop{$ln}.="$v|$pop{$v};"
	}
}

foreach $ln (keys %cache_count2)
{
	my $total=0;
	my $pure_total=0;
	foreach $bt (keys %{$cache_count2{$ln}})
	{
		
		for ($i=0;$i<$N_first_hits;$i++)
		{
			if (defined $cache_count2{$ln}{$bt}{"one$i.sz"})
			{
				$hit2{$ln}++;
			}
		}
		my $cur_sz=scalar(keys %{$cache_count2{$ln}{$bt}});
		$total+=$cur_sz;
		foreach $pp (keys %{$cache_count2{$ln}{$bt}})
		{
			$pure_total+=$cache_count2{$ln}{$bt}{$pp};
		}
	}
	$hit{$ln}=$total;
	$pure_hit{$ln}=$pure_total;
}

print STDERR "\n".localtime()." - Done with counting caches #2\n";

foreach $k (keys %logic)
{
	my $ln;
	my $out_ip;
	my $test;
	my $bt;
	($ln,$out_ip,$test,$bt)=split/ /,$k;
	$test=~tr/\-/_/;

	my $good=0;
	my $bad=0;

	if ($brute and not (($test eq "test_ak1") or ($test eq "test_w11") or ($test eq "test_w11bis") or ($test eq "test_dname")))
	{
		my %three_good;
		my %three_bad;
		while ($logic{$k}{victim}=~/<three([0-9]{0,2})>/g)
		{
			$three_bad{$1}++;
		}
		$bad=scalar(keys %three_bad);
		while ($logic{$k}{attacker}=~/<three([0-9]{0,2})>/g)
		{
			$three_good{$1}++;
		}
		$good=scalar(keys %three_good);
		$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
		$result{"$ln,$out_ip"}{$test}{good}+=$good;
		next;
	}

	if ($brute and (($test eq "test_ak1") or ($test eq "test_w11") or ($test eq "test_w11bis") or ($test eq "test_dname")))
	{
		my %one_attacker;
		my %one_victim;
		while ($logic{$k}{victim}=~/<one([0-9]{0,2})>/g)
		{
			$one_victim{$1}++;
		}
		while ($logic{$k}{attacker}=~/<one([0-9]{0,2})>/g)
		{
			$one_attacker{$1}++;
		}
		
		my $good=0;
		my $bad=0;
		foreach $i (keys %one_victim)
		{
			if (exists $one_attacker{$i})
			{
				$good++;
			}
			else
			{
				$bad++;
			}
		}
		$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
		$result{"$ln,$out_ip"}{$test}{good}+=$good;
		next;
	}
	
	if  (($test eq "test_ak1") or ($test eq "test_w11") or ($test eq "test_w11bis"))
	{
		# special treatment for the delayed tests
		
		if (($logic{$k}{victim}=~/<one1>/) and ($logic{$k}{victim}=~/<zwei1>|<zwei\.one1>/))
		{
			
				#if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
				{
					print STDERR "ln=$ln, test=$test, bt=$bt - #one1 at parent = ".(()=$logic{$k}{parent}=~/<one1>/g)."\n";
				}
			next if ((()=$logic{$k}{parent}=~/<one1>/g)>1);
			# These specific tests are unlikely to trigger any rejections from resolvers (they're 100% Kosher). So any resolve-from-root means switching caches or packet loss, i.e. we can DISCARD.
			# However, if the resolution stops at the parent, it may be an error (or not), so we continue.
			#next if (((()=$logic{$k}{parent}=~/<zwei|zwei\.one1>/g)>0) and ((()=$logic{$k}{victim}=~/<zwei|zwei\.one1>/g)>1));

			my $min_parent_two_t=2000000000;
			
			my $pattern="<(zwei1|zwei\\.one1):([0-9\\.]+)>";
			while($logic_time{$k}{parent}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_parent_two_t)
				{
					$min_parent_two_t=$tt;
				}
			}
			my $min_victim_two_t=2000000000;
			my $max_victim_two_t=-1;
			while($logic_time{$k}{victim}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_victim_two_t)
				{
					$min_victim_two_t=$tt;
				}
				if ($tt>$max_victim_two_t)
				{
					$max_victim_two_t=$tt;
				}
			}

				if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
				{
					print STDERR "ln=$ln, test=$test, bt=$bt - min_parent_two_t = $min_parent_two_t  max_victim_two_t = $max_victim_two_t\n";
				}

			if  (($min_parent_two_t<2000000000) and ($min_parent_two_t<$max_victim_two_t))
			{
				# There is a resolution path going through the parent and reaching the victim
				next;
			}

			my $two_time=-1;
			while ($logic_time{$k}{victim}=~/<(zwei1|zwei\.one1):([0-9\.]+)>/g)
			{
				my $tt=$2;
				if ($tt>$two_time)
				{
					$two_time=$tt;
				}
			}

			my $closest_one_time=-1;
			my $max_one_time=-1;
			while($logic_time{$k}{victim}=~/<one1:([0-9\.]+)>/g)
			{
				my $cur_time=$1;
				if ($cur_time>$max_one_time)
				{
					$max_one_time=$cur_time;
				}
				next if ($cur_time>$two_time);
				if ($cur_time>$closest_one_time)
				{
					$closest_one_time=$cur_time;
				}
			}
			
			if ($two_time>$closest_one_time+$ttl-$dt)
			{
				# The poisoning payload (two) arrived after the genuine record (one) has expired. DISCARD.
				if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
				{
					print STDERR "ln=$ln, test=$test, bt=$bt - $two_time > $closest_one_time+$ttl-$dt\n";
				}
				next;
			}

			my $min_one_time_attacker=2000000000;
			my $max_one_time_attacker=-1;
			while($logic_time{$k}{attacker}=~/<one1:([0-9\.]+)>/g)
			{
				my $cur_time=$1;
				if ($cur_time>$max_one_time_attacker)
				{
					$max_one_time_attacker=$cur_time;
				}
				if ($cur_time<$min_one_time_attacker)
				{
					$min_one_time_attacker=$cur_time;
				}
			}
			
			if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
			{
				if ($max_one_time>$two_time+$dt)
				{
					print STDERR "*** ";
				}
				print STDERR "ln=$ln, test=$test, bt=$bt - max_one_time=$max_one_time, max_one_time_attacker=$max_one_time_attacker, two_time=$two_time\n";
			}

			if ($max_one_time>$two_time+$dt)
			{
				# There's a hit to "one" on the victim, after the poisoning payload. FAIL.
				if ($max_one_time_attacker>$two_time+$dt)
				{
					# But if there's also a hit on one on the attacker, count it. (SUCCESS+FAIL).
					$good+=$count_goodbad_as_good;
					$bad+=$count_goodbad_as_bad;
				}
				else
				{
					$bad=1;
				}
			}
			elsif ($max_one_time_attacker>0)
			{
				# No hit on the victim, but there's a hit on the attacker. SUCCESS.
				$good=1;
			}
			else
			{
				# No hits on "one" after the poisoning payload. DISCARD.
				#print "Not a valid test at ln=$ln test=$test bt=$bt (i=$i) - no post-poison hit to attacker nor to victim\n";
			}
		}
	}
	elsif  ($test eq "test_dname")
	{
		# special treatment for the delayed tests - DNAME
		
		if (($logic{$k}{victim}=~/<one1>/) and ($logic{$k}{victim}=~/<zwei>/))
		{
			if ($logic{$k}{victim}=~/<ns>|<ns2>/)
			{
				$bad=1;
				$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
				$result{"$ln,$out_ip"}{$test}{good}+=$good;
				next;
			}
			#my $double1=()=($logic{$k}{victim}=~/<zwei>/g);
			#if ($double1>1)
			#{
			#	#print "Double ($double1) found at ln=$ln test=$test bt=$bt (i=$i)\n";
			#	next;
			#}

			my $min_parent_two_t=2000000000;
			
			my $pattern;
			$pattern="<(zwei):([0-9\\.]+)>";
			
			while($logic_time{$k}{parent}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_parent_two_t)
				{
					$min_parent_two_t=$tt;
				}
			}
			my $min_victim_two_t=2000000000;
			my $max_victim_two_t=-1;
			while($logic_time{$k}{victim}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_victim_two_t)
				{
					$min_victim_two_t=$tt;
				}
				if ($tt>$max_victim_two_t)
				{
					$max_victim_two_t=$tt;
				}
			}
			if  (($min_parent_two_t>$min_victim_two_t) and ($min_parent_two_t<$max_victim_two_t) and ($min_parent_two_t<2000000000))
			{
				# Possibly a true failure - there's a from-root resolution of "two" *after* the first resolution for "two", and the resolution reaches the victim.
				# This can also happen due to packet loss (BIND), but we prefer to err to the FAIL side. So FAIL.
				# We do check that the resolution arrives at the victim.
				
				$bad=1;
				$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
				$result{"$ln,$out_ip"}{$test}{good}+=$good;
				next;
			}


			my $min_one_time=2000000000;
			my $max_one_time=0;
			while($logic_time{$k}{victim}=~/<one1:([0-9\.]+)>/g)
			{
				my $cur_time=$1;
				if ($cur_time>$max_one_time)
				{
					$max_one_time=$cur_time;
				}
				next if ($cur_time>($max_victim_two_t+$dt));
				if ($cur_time<$min_one_time)
				{
					$min_one_time=$cur_time;
				}
			}
			if ($min_one_time>$max_victim_two_t+$dt)
			{
				next;  # no proper seeding in this test
			}
			
			if ($max_victim_two_t>$min_one_time+$ttl-$dt)
			{
				#print "Out of cache at ln=$ln test=$test bt=$bt (i=$i): min_one_time=$min_one_time two_time=$two_time, dt=".($two_time-$min_one_time)."\n";
				next;
			}

			next if ((()=$logic{$k}{parent}=~/<one1|zwei>/g)>1);
			
			my $isgood=0;
			my $isbad=0;
			if ($logic{$k}{attacker}=~/<one1>/)
			{
				$isgood=1;
			}
			
			if ($max_one_time>$max_victim_two_t+$dt)
			{
				$isbad=1;
			}
			else
			{
				#print "Not a valid test at ln=$ln test=$test bt=$bt (i=$i) - no post-poison hit to attacker nor to victim\n";
			}
			if ($isgood and $isbad)
			{
				$good+=$count_goodbad_as_good;
				$bad+=$count_goodbad_as_bad;
			}
			else
			{
				$good+=$isgood;
				$bad+=$isbad;
			}
		}
	}
	else
	{
		if ((($logic{$k}{victim}=~/<one[0-9]?>/) or $oneless) and ($logic{$k}{victim}=~/<two[0-9]?>|<ns2[0-9]?>|<two[0-9]?\.sub[0-9]?>|<ns\.sub[0-9]?>/))
		{
			if  (($test=~/^test_ns0(_auth)?$/) and ($logic{$k}{victim}=~/<ns2>/))
			{
				# In test-ns0/test-ns0-auth, new BIND on first hit AFTER poisoning (i.e. three1) attempts to resolve ns2, fails, and returns SERVFAIL without hitting three1 anywhere.
				# So we need to count this as FAIL even though there's no hit on three.
				$bad=1;
				$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
				$result{"$ln,$out_ip"}{$test}{good}+=$good;
				next;

			}
			if (not (($logic{$k}{victim}=~/<three1>/) or ($logic{$k}{attacker}=~/<three1>/)))
			{
				# No hit on three in victim/attacker. DISCARD.
				next;
			}
			
			my $min_parent_two_t=2000000000;
			
			my $pattern;
			if ($test=~/^test_ns(_auth)?$/)
			{
				$pattern="<(ns2):([0-9\\.]+)>";
			}
			else
			{
				$pattern="<(two[0-9]?|two[0-9]?\\.sub[0-9]?|ns\\.sub[0-9]?):([0-9\\.]+)>";
			}
			while($logic_time{$k}{parent}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_parent_two_t)
				{
					$min_parent_two_t=$tt;
				}
			}
			my $min_victim_two_t=2000000000;
			my $max_victim_two_t=-1;
			while($logic_time{$k}{victim}=~/$pattern/g)
			{
				my $tt=$2;
				if ($tt<$min_victim_two_t)
				{
					$min_victim_two_t=$tt;
				}
				if ($tt>$max_victim_two_t)
				{
					$max_victim_two_t=$tt;
				}
			}
			if  (($min_parent_two_t>$min_victim_two_t) and ($min_parent_two_t<$max_victim_two_t) and ($min_parent_two_t<2000000000))
			{
				# Possibly a true failure - there's a from-root resolution of "two" *after* the first resolution for "two", and the resolution reaches the victim.
				# This can also happen due to packet loss (BIND), but we prefer to err to the FAIL side. So FAIL.
				# We do check that the resolution arrives at the victim.
					if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
					{
						print STDERR "(FAILING zzz) ln=$ln, test=$test, bt=$bt - $min_parent_two_t < 2000000000\n";
					}
				
				$bad=1;
				$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
				$result{"$ln,$out_ip"}{$test}{good}+=$good;
				next;
			}
				
			# Make sure there's no extra resolutions from-parent, as this indicates multiple caches.
			next if ((()=$logic{$k}{parent}=~/<one1>/g)>1);
			if  (($min_parent_two_t<2000000000) and ($min_parent_two_t<$max_victim_two_t))
			{
				# There is a resolution path going through the parent and reaching the victim - so probably a cache-switch. DISCARD
					if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
					{
						print STDERR "(DISCARDING vvv) ln=$ln, test=$test, bt=$bt \n";
					}
				next;
			}
			#next if (($logic{$k}{parent}=~/<two[0-9]?>|<two[0-9]?\.sub[0-9]?>|<ns\.sub[0-9]?>/) or (($test=~/^test_ns(_auth)?$/) and ($logic{$k}{parent}=~/<ns2>/)));
			next if ($logic{$k}{parent}=~/<three1>/);

			if ($logic{$k}{victim}=~/<three1>/)
			{
				$bad=1;
			}
			if ($logic{$k}{attacker}=~/<three1>/)
			{
				$good=1;
			}


			if (0)
			{
				my $min_victim_two_t=2000000000;
				while($logic_time{$k}{victim}=~/<(two[0-9]?|two[0-9]?\.sub[0-9]?|ns\.sub[0-9]?):([0-9\.]+)>/g)
				{
					my $tt=$2;
					if ($tt<$min_victim_two_t)
					{
						$min_victim_two_t=$tt;
					}
				}

				if ($test=~/^test_ns(_auth)?$/)
				{
					if ((()=($logic{$k}{victim}=~/<ns2[0-9]?>/g))>1)
					{
						if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
						{
							print STDERR "(FAILING 000) ln=$ln, test=$test, bt=$bt - $max_victim_ns_t > $min_victim_two_t\n";
						}
						$bad=1;
						$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
						$result{"$ln,$out_ip"}{$test}{good}+=$good;
						next;
					}
				}
				elsif ($logic{$k}{victim}=~/<ns>|<ns2>/)
				{
					my $max_victim_ns_t=0;
					while($logic_time{$k}{victim}=~/<(ns|ns2):([0-9\.]+)>/g)
					{
						my $tt=$2;
						if ($tt>$max_victim_ns_t)
						{
							$max_victim_ns_t=$tt;
						}
					}
					if ($max_victim_ns_t>$min_victim_two_t)
					{
						if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
						{
							print STDERR "(FAILING xxx) ln=$ln, test=$test, bt=$bt - $max_victim_ns_t > $min_victim_two_t\n";
						}

						$bad=1;
						$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
						$result{"$ln,$out_ip"}{$test}{good}+=$good;
						next;
					}
				}
				my $double1=()=($logic{$k}{victim}=~/<two[0-9]?>|<two[0-9]?\.sub[0-9]?>|<ns\.sub[0-9]?>/g);
				#my $double2=()=($logic{$k}{victim}=~/<ns2[0-9]?>/g);
				
				my $min_parent_two_t=2000000000;
				while($logic_time{$k}{parent}=~/<(two[0-9]?|two[0-9]?\.sub[0-9]?|ns\.sub[0-9]?):([0-9\.]+)>/g)
				{
					my $tt=$2;
					if ($tt<$min_parent_two_t)
					{
						$min_parent_two_t=$tt;
					}
				}
				
				
				if ($min_parent_two_t<$min_victim_two_t)
				{
					# Just a cache switch - discard.
						if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
						{
							print STDERR "(DISCARDING yyy) ln=$ln, test=$test, bt=$bt - $min_parent_two_t < $min_victim_two_t\n";
						}
					next;
				}
				elsif ($min_parent_two_t<2000000000)
				{
					# Possibly a true failure
						if (($ln eq $DBG_LINE) and ($test eq $DBG_TEST))
						{
							print STDERR "(FAILING zzz) ln=$ln, test=$test, bt=$bt - $min_parent_two_t < 2000000000\n";
						}
					
					$bad=1;
					$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
					$result{"$ln,$out_ip"}{$test}{good}+=$good;
					next;
				}
				#if ((($double1>1)  or ($double2>1)) and (($test ne "test_b4") and ($test ne "test_u1_auth") and ($test ne "test_u3_3")) and $omit_doubles) 
				#{
				#	if  (($ln eq "32") and ($test eq "test_dname_weak"))
				#	{
				#		print STDERR "Now at test_u3_4 - xxx\n";
				#	}
				#	next;
				#}
				my %three_bad;
				while($logic{$k}{victim}=~/<(three1)>/g)
				{
					$three_bad{$1}++;
				}
				$bad=scalar(keys %three_bad);
				
				my %three_good;
				my $double=0;
				while($logic{$k}{attacker}=~/<(three1)>/g)
				{
					$three_good{$1}++;
					if ($three_good{$1}>1)
					{
						$double=1;
					}
				}
				if ($double and $omit_doubles)
				{
					next;
				}
				$good=scalar(keys %three_good);
				
				# Make sure there's no extra resolutions from-patent, as this indicates multiple caches.
				next if ((()=$logic{$k}{parent}=~/<one1>/g)>1);
				next if (($logic{$k}{parent}=~/<two[0-9]?>|<two[0-9]?\.sub[0-9]?>|<ns\.sub[0-9]?>/) or  (($test=~/^test_ns(_auth)?$/) and ($logic{$k}{parent}=~/<ns2>/)));
				next if ($logic{$k}{parent}=~/<three1>/);
				
				if  (($test=~/test_ns0/) and ($good==0) and ($bad==0) and ($logic{$k}{victim}=~/<ns2>/))
				{
					# This is new BIND, the test probably did fail...
					$bad=1;
				}
				foreach $xx (keys %three_bad)
				{
					if (defined $three_good{$xx})
					{
						$good+=$count_goodbad_as_good-1;
						$bad+=$count_goodbad_as_bad-1;
					}
				}
				
				#if ($good and $bad)
				#{
				#	if (not ($test=~/test_ns.*_auth/))
				#	{
				#		#print "Ahem - both good and bad at $k\n";
				#		$anomaly{"$ln,$out_ip"}++;
				#	}
				#}
			}
		}
	}
	$result{"$ln,$out_ip"}{$test}{total}+=($good + $bad);
	$result{"$ln,$out_ip"}{$test}{good}+=$good;
}

print STDERR "\n".localtime()." - Done with logic\n";

foreach $k (keys %ns)
{
	my $ln;
	my $out_ip;
	my $test;
	my $bt;
	($ln,$out_ip,$bt)=split/ /,$k;
	$found=0;
	if ($ns{"$ln $out_ip $bt"}=~/<found>/)
	{
		$found=1;
	}
	$good=0;
	if ($ns{"$ln $out_ip $bt"}=~/<NS>/)
	{
		$good=1;
	}
	$result{"$ln,$out_ip"}{"test_ns_a_ns"}{total}+=$found;
	$result{"$ln,$out_ip"}{"test_ns_a_ns"}{good}+=$good;
}

foreach $k (keys %a)
{
	my $ln;
	my $out_ip;
	my $test;
	my $bt;
	($ln,$out_ip,$bt)=split/ /,$k;
	$found=0;
	if ($a{"$ln $out_ip $bt"}=~/<found>/)
	{
		$found=1;
	}
	$good=0;
	if ($a{"$ln $out_ip $bt"}=~/<A-ns>/)
	{
		$good=1;
	}
	$result{"$ln,$out_ip"}{"test_ns_a_a"}{total}+=$found;
	$result{"$ln,$out_ip"}{"test_ns_a_a"}{good}+=$good;
}

foreach $k (keys %x_ns)
{
	my $ln;
	my $out_ip;
	my $test;
	my $bt;
	($ln,$out_ip,$bt)=split/ /,$k;
	$found=0;
	if ($x_ns{"$ln $out_ip $bt"}=~/<found>/)
	{
		$found=1;
	}
	$good=0;
	if ($x_ns{"$ln $out_ip $bt"}=~/<NS>/)
	{
		$good=1;
	}
	$result{"$ln,$out_ip"}{"test_x_ns_a_ns"}{total}+=$found;
	$result{"$ln,$out_ip"}{"test_x_ns_a_ns"}{good}+=$good;
}

foreach $k (keys %x_a)
{
	my $ln;
	my $out_ip;
	my $test;
	my $bt;
	($ln,$out_ip,$bt)=split/ /,$k;
	$found=0;
	if ($x_a{"$ln $out_ip $bt"}=~/<found>/)
	{
		$found=1;
	}
	$good=0;
	if ($x_a{"$ln $out_ip $bt"}=~/<A-ns>/)
	{
		$good=1;
	}
	$good_AAAA=0;
	if ($x_a{"$ln $out_ip $bt"}=~/<AAAA-ns>/)
	{
		$good_AAAA=1;
	}
	if (($good eq 0) and ($good_AAAA eq 1) and $omit_doubles)
	{
		next;
	}
	$result{"$ln,$out_ip"}{"test_x_ns_a_a"}{total}+=$found;
	$result{"$ln,$out_ip"}{"test_x_ns_a_a"}{good}+=$good;
}

print STDERR "\n".localtime()." - Done with analyzing NS/A\n";

sub bind_from_qid
{
	my $txid=shift;
	my $second_txid=shift;
	
	if (($txid & 1)!=0)
	{
		return -1;
	}

		my $result=0;
	for (my $bind_variant=0;$bind_variant<2;$bind_variant++)
	{
		# For BIND9 v9.2.3-9.4.1:
		#$tap1=0x80000057;
		#$tap2=0x80000062;

		# For BIND9 v9.0.0-9.2.2:
		# $tap1=0xc000002b; # (0x80000057>>1)|(1<<31)
		# $tap2=0xc0000061; # (0x800000c2>>1)|(1<<31)
		# One bit shift (assuming the two lsb's are 0 and 0)
		
		$tap1=(0x80000057,0xc000002b)[$bind_variant];
		$tap2=(0x80000062,0xc0000061)[$bind_variant];
		
		for (my $msb=0;$msb<(1<<1);$msb++)
		{
			if (((($msb<<15)|($txid>>1)) & 0xFFFF) == $second_txid)
			{
				#return $bind_variant;
				$result|=(1<<$bind_variant);
			}
		}

		# Two bit shift (assuming the two lsb's are 1 and 1)
		# First shift (we know the lsb is 1 in both LFSRs):
		my $v=$txid;
		$v=($v>>1)^$tap1^$tap2;
		my $v1;
		my $v2;
		if (($v & 1)==0)
		{
			# After the first shift, the lsb becomes 0, so the two LFSRs now have
			# identical lsb's: 0 and 0 or 1 and 1
			# Second shift:
			$v1=($v>>1); # 0 and 0
			$v2=($v>>1)^$tap1^$tap2; # 1 and 1
		}
		else
		{
			# After the first shift, the lsb becomes 1, so the two LFSRs now have
			# different lsb's: 1 and 0 or 0 and 1
			# Second shift:
			$v1=($v>>1)^$tap1; # 1 and 0
			$v2=($v>>1)^$tap2; # 0 and 1
		}

		# Also need to enumerate over the 2 msb's we are clueless about
		for (my $msbits=0;$msbits<(1<<2);$msbits++)
		{
			if (((($msbits<<14)|$v1) & 0xFFFF) == $second_txid)
			{
				#return $bind_variant;
				$result|=(1<<$bind_variant);
			}
			if (((($msbits<<14)|$v2) & 0xFFFF) == $second_txid)
			{
				#return $bind_variant;
				$result|=(1<<$bind_variant);
			}
		}
	}
	
	return $result;
}

foreach $ln (keys %qid_stat)
{
	foreach $t (keys %{$qid_stat{$ln}})
	{
		my $first=$qid_stat{$ln}{$t}{A};
		my $second=$qid_stat{$ln}{$t}{A6};
		if (not defined $second)
		{
			$second=$qid_stat{$ln}{$t}{AAAA};
		}
		if ((not defined $first) or (not defined $second))
		{
			#print "At line $ln, t=$t - skipping ($first, $second)\n";
			next;
		}
		#print "At line $ln, t=$t, first=$first, second=$second, bindfunc returned ".bind_from_qid($first,$second)."\n";
		
		$qid_ln{$ln}{bind_from_qid($first,$second)}++;
	}
}

foreach $ln (keys %qid_ns_stat)
{
	foreach $bt (keys %{$qid_ns_stat{$ln}})
	{
		my $first=$qid_ns_stat{$ln}{$bt}{nsx}{A};
		if  ((not defined $first) or (defined $qid_ns_stat{$ln}{$bt}{nsx}{A6}) or (defined $qid_ns_stat{$ln}{$bt}{nsx}{AAAA}))
		{
			next;
		}
		my $second=$qid_ns_stat{$ln}{$bt}{nsy}{A};
		if  ((not defined $second) or (defined $qid_ns_stat{$ln}{$bt}{nsy}{A6}) or (defined $qid_ns_stat{$ln}{$bt}{nsy}{AAAA}))
		{
			next;
		}
		$qid_ln{$ln}{bind_from_qid($first,$second)}++;
	}
}

print STDERR "\n".localtime()." - Done with QIDs\n";

sub port_bucket
{
	my $delta=shift;
	
	return int(abs($delta)/$port_bucket_size);
}

foreach $ln (keys %xport_stat)
{
	foreach $t (keys %{$xport_stat{$ln}})
	{
		my $first=$xport_stat{$ln}{$t}{A};
		my $second=$xport_stat{$ln}{$t}{A6};
		if (not defined $second)
		{
			$second=$xport_stat{$ln}{$t}{AAAA};
		}
		if ((not defined $first) or (not defined $second))
		{
			#print "At line $ln, t=$t - skipping ($first, $second)\n";
			next;
		}
		#print "At line $ln, t=$t, first=$first, second=$second, bindfunc returned ".bind_from_qid($first,$second)."\n";
		
		$port_ln{$ln}{port_bucket($second-$first)}++;
	}
}

foreach $ln (keys %port_ns_stat)
{
	foreach $bt (keys %{$port_ns_stat{$ln}})
	{
		my $first=$port_ns_stat{$ln}{$bt}{nsx}{A};
		if  ((not defined $first) or (defined $port_ns_stat{$ln}{$bt}{nsx}{A6}) or (defined $port_ns_stat{$ln}{$bt}{nsx}{AAAA}))
		{
			next;
		}
		my $second=$port_ns_stat{$ln}{$bt}{nsy}{A};
		if  ((not defined $second) or (defined $port_ns_stat{$ln}{$bt}{nsy}{A6}) or (defined $port_ns_stat{$ln}{$bt}{nsy}{AAAA}))
		{
			next;
		}
		$port_ln{$ln}{port_bucket($second-$first)}++;
	}
}


print STDERR "\n".localtime()." - Done with ports\n";

foreach $k (keys %result)
{
	my $ln;
	my $ip;
	($ln,$ip)=split/,/,$k;
	my $ctr=0;
	foreach $kk (keys %{$name_seen{$ln}})
	{
		if ($kk=~/\.(test-dname-weak|test-ns0|test-ns0-auth|test-ns|test-ns-auth|test-ns2|test-ns2-auth|test-b4|test-u1-auth|test-u3-2|test-u3-3|test-u3-4|test-w7|test-w8)\./)
		{
			$ctr++;
		}
	}
	$attack_hits_per_line{$ln}=$ctr;
}

my %sb_seen;
my %sb_decide;
print '"part","total hit count","attack hit count","line","USE LINE?","representor","origin IP","country","ISP","IP (UNUSED)","outbound IPs","outbound ISPs","outbound ASNs","outbound countries","time (unix)","time","ref. cache count (max) (UNUSED)","ref. cache count (maxpop)","ans. cache count (max) (UNUSED)","ans. cache count (maxpop)","hits","batches seen","hit rate","hit2","hit2 rate","pure hit rate","(blank)","test_dname_weak","v","test_ns0","v","test_ns0_auth","v","test_ns","v","test_ns_auth","v","test_ns2","v","test_ns2_auth","v","test_b4","v","test_u1_auth","v","test_u3_2","v","test_u3_3","v","test_u3_4","v","test_w7","v","test_w8","v","test_ns_a_ns","v","test_ns_a_a","v","test_x_ns_a_ns","v","test_x_ns_a_a","v","test_dname (DELAYED)","v","test_ak1 (DELAYED)","v","test_w11 (DELAYED)","v","test_w11bis (DELAYED)","v","(blank)","nonzero columns","good columns","anomalous columns","num_tests","sig mask","sig","matches","sig guess","sig guess match","sig_multimatch","xor_multimatch","multimatch names","min. Hamming","hamming guess","FINAL signame","version.bind","min_port","max_port","port_range","port strategy","distinctive ports","BIND QID algo","QID algo match count","total even QIDs","QID match ratio","best_port_delta","amount","total delta tests"'."\n";
#foreach $k (sort {($first_encounter{(split/,/,$a)[0]} <=> $first_encounter{(split/,/,$b)[0]}) || ((split/,/,$a)[0] <=> (split/,/,$b)[0]) || (ip_to_int((split/,/,$a)[1]) <=> ip_to_int((split/,/,$b)[1]))} keys %result)
foreach $k (sort {((split/,/,$a)[0] <=> (split/,/,$b)[0]) || (ip_to_int((split/,/,$a)[1]) <=> ip_to_int((split/,/,$b)[1]))} keys %result)
{
	my $ln;
	my $ip;
	($ln,$ip)=split/,/,$k;
	#print "$k : $result{$k}{good} out of $result{$k}{total}\n";
	#print "ln=$ln, origin_ip=$origin_ip{$ln}\n";
	#print "... isp_for_ip=".isp_for_ip($origin_ip{$ln})."\n";
	$ln=~/^([0-9]*)(b|s)$/;
	my $ln_num=$1;
	my $ln_size=$2;
	my $use_line=0;
	
	
	
	# XXXXX
	#next if ((not defined ($result{$ln_num."s,[MERGED]"})) or (not defined ($result{$ln_num."b,[MERGED]"})));
	
	$sb_seen{$ln_num}.=$ln_size;
	#if  (($ln_size eq "b") and ($cache_maxpop{$ln}>2))
	#{
	#	$use_line=1;
	#	$sb_decide{$ln_num}++;
	#}
	#if  (($ln_size eq "s") and ($cache_maxpop{$ln}<=2))
	#{
	#	$use_line=1;
	#	$sb_decide{$ln_num}++;
	#}
	
	if (($attack_hits_per_line{$ln_num."s"}>=800) and ($attack_hits_per_line{$ln_num."b"}>=800))
	{
		if  (($ln_size eq "b") and ($cache_maxpop{$ln_num."s"}>2))
		{
			$use_line=1;
			$sb_decide{$ln_num}++;
		}
		if  (($ln_size eq "s") and ($cache_maxpop{$ln_num."s"}<=2))
		{
			$use_line=1;
			$sb_decide{$ln_num}++;
		}
		
	}
	
	$sb_decide{$ln_num}+=0;
	
	# XXXXX
	
	my $rep=0;
	if (defined $seenln{$origin_ip{$ln}})
	{
		if ($ln_num==$seenln{$origin_ip{$ln}})
		{
			$rep=1;
		}
	}
	else
	{
		$seenln{$origin_ip{$ln}}=$ln_num;
		$rep=1;
	}
	print '"'.$part.'",'.scalar(keys %{$name_seen{$ln}}).',"'.$attack_hits_per_line{$ln}.'","'.$ln.'",'.$use_line.",$rep,$origin_ip{$ln},$country{$ln},".'"'.(split/ /,isp_for_ip($origin_ip{$ln}),3)[2].'"'.",$ip";
	print ',"';
	$ever_reported{$ln}++;
	my @z;
	foreach $zz (sort {$ip_list{$ln}{$b}<=>$ip_list{$ln}{$a}} keys %{$ip_list{$ln}})
	{
		push @z,$zz."#".$ip_list{$ln}{$zz};
	}
	print join("|",@z).'","';
	
	my @z2;
	foreach $zz (sort {$isp_list{$ln}{$b}<=>$isp_list{$ln}{$a}} keys %{$isp_list{$ln}})
	{
		push @z2,$zz."#".$isp_list{$ln}{$zz};
	}
	print join("|",@z2).'","';
	
	my @z3;
	foreach $zz (sort {$asn_list{$ln}{$b}<=>$asn_list{$ln}{$a}} keys %{$asn_list{$ln}})
	{
		push @z3,$zz."#".$asn_list{$ln}{$zz};
	}
	print join("|",@z3).'","';
	
	my @z4;
	foreach $zz (sort {$country_list{$ln}{$b}<=>$country_list{$ln}{$a}} keys %{$country_list{$ln}})
	{
		push @z4,$zz."#".$country_list{$ln}{$zz};
	}
	print join("|",@z4).'"';
	
	my $t=$first_encounter{(split/,/,$k)[0]};
	my $nc=$cache_maxpop{$ln};
	#my $nc=($cache_maxpop{$ln}>1)?$cache_maxpop{$ln}-1:1;
	print ',"'.$t.'","'.gmtime($t).'"'.",$cache{$ln},$nc,$acache{$ln},$acache_maxpop{$ln},$hit{$ln},".(scalar(keys %{$btct{$ln}})).",".(scalar(keys %{$btct{$ln}})>0?($hit{$ln}/(scalar(keys %{$btct{$ln}})*10)):"say what?").",$hit2{$ln},".(scalar(keys %{$btct{$ln}})>0?($hit2{$ln}/(scalar(keys %{$btct{$ln}})*$N_first_hits)):"say what?").",".(($pure_hit{$ln}==0)?"":($hit{$ln}/$pure_hit{$ln}));
	if (not defined $cache_count{$ln})
	{
		# XXXXX
		#print "**** Whoa - this server is so totally not responsive... ****\n";
		#next;
	}
	my $sig=0;
	my $sig_guess=0;
	my $sigmask=0;
	my $sig_multiguess=0;
	my $xor_multiguess=0;
	my $undet=0;
	my $n=0;
	my $num_test=0;
	my $columns=0;
	my $anom_columns=0;
	my $good_columns=0;
	my $maybe_pdns=0;
	print ","; # blank
	foreach $kk ("test_dname_weak","test_ns0","test_ns0_auth","test_ns","test_ns_auth","test_ns2","test_ns2_auth","test_b4","test_u1_auth","test_u3_2","test_u3_3","test_u3_4","test_w7","test_w8","test_ns_a_ns","test_ns_a_a","test_x_ns_a_ns","test_x_ns_a_a","test_dname","test_ak1","test_w11","test_w11bis")
	{
		my $in_effect=0;
		if ($include_delayed or (($kk ne "test_dname") and ($kk ne "test_ak1") and ($kk ne "test_w11") and ($kk ne "test_w11bis")))
		{
			$in_effect=1;
		}

		if ($result{$k}{$kk}{total}>0)
		{
			#if (not defined $cache{$ln})
			#{
			#	$cache{$ln}=1;
			#}
			
			my $p=$hit2{$ln}/(scalar(keys %{$btct{$ln}})*$N_first_hits);
			#my $p=$hit{$ln}/(scalar(keys %{$btct{$ln}})*10);
			my $ex=$result{$k}{$kk}{total}*$p;
			my $sigma=sqrt($result{$k}{$kk}{total}*$p*(1-$p));
			if ($sigma eq 0)
			{
				$sigma=0.000001;
			}
			my $z=($result{$k}{$kk}{good}-$ex)/$sigma;
			#$show_z=1;
			$show_z=0;
			my $r="";
			my $r_guess="";
			my $multi_guess=0;
			my $xor=0;
			
			if ($brute)
			{
				if ($result{$k}{$kk}{good}/$result{$k}{$kk}{total}>0.1)
				{
					$r_guess=1;
					if ($result{$k}{$kk}{good}/$result{$k}{$kk}{total}<0.7)
					{
						if ($kk=~/^(test_ns_a_ns|test_ns_a_a|test_x_ns_a_ns|test_x_ns_a_a)$/)
						{
							$multi_guess=1;
						}
						else
						{
							$xor=1;
						}
					}
					else
					{
						$multi_guess=1;
					}
				}
				else
				{
					$r_guess=0;
					$multi_guess=0;
				}
			}
			else
			{
				if ($result{$k}{$kk}{good}/$result{$k}{$kk}{total}>0.5)
				{
					$r_guess=1;
				}
				else
				{
					$r_guess=0;
				}
			}
			# # Override for this test...
			#if ($kk eq "test_x_ns_a_a")
			#{
			#	$r_guess=1;
			#}
			
			my $has_data=0;
			
			if ($kk=~/^(test_ns_a_ns|test_ns_a_a|test_x_ns_a_ns|test_x_ns_a_a)$/)
			{
				$has_data=1;
				$show_z=0;
				if  ($result{$k}{$kk}{good} eq $result{$k}{$kk}{total})
				{
					$r=1;
					$sig|=(1<<$n);
				}
				elsif ($result{$k}{$kk}{good} eq 0)
				{
					$r=0;
					$sig|=(0<<$n);
				}
				else
				{
					$r='U';
					#if ($kk ne "test_x_ns_a_a")
					{
						$undet=1;
					}
				}
			}
			elsif ($brute)
			{
				$has_data=1;
				$show_z=0;
				if ($in_effect)
				{
					$columns++;
				}
				$num_test+=$result{$k}{$kk}{total};
				if ($result{$k}{$kk}{good}<=(1/3)*$result{$k}{$kk}{total})
				{
					$r=0;
				}
				elsif ($result{$k}{$kk}{good}>=(2/3)*$result{$k}{$kk}{total})
				{
					$r=1;
					$good_columns++;
				}
				else
				{
					if ($kk eq "test_ns_auth")
					{
						$maybe_pdns=1;
						$r=1;
						$good_columns++;
					}
					else
					{
						$r='U';
						$undet=1;
						$anom_columns++;
					}
				}
			}
			else
			{
				if ($result{$k}{$kk}{total}>=4)
				{
					$has_data=1;
					my $delta=1;
					if ($in_effect)
					{
						$columns++;
					}
					$num_test+=$result{$k}{$kk}{total};
					if  (($result{$k}{$kk}{good}==0) or (($kk=~/auth/) and ($result{$k}{$kk}{good}<=$delta)))
					{
						# A packet loss for "one" in the "...-auth" tests leads to the resolver caching the referral data with rank 3 (rather than 5)
						# So more vulnerable to attacks. Hence we treat a small percentage of SUCCESS as a global failure.
						$r=0;
					}
					elsif ($result{$k}{$kk}{good}>=$result{$k}{$kk}{total}-$delta)
					{
						$r=1;
						$good_columns++;
					}
					else
					{
						$r='U';
						$undet=1;
						$anom_columns++;
					}
				}
			}
				
			if ($in_effect and $has_data)
			{
				$sig_guess|=($r_guess<<$n);
				$sig_multiguess|=($multi_guess<<$n);
				$xor_multiguess|=($xor<<$n);
				$sigmask|=(1<<$n);
				$sig|=($r<<$n);
				#if ($kk eq "test_x_ns_a_a")
				#{
				#	$sig|=(1<<$n);
				#}	
			}

			print ",".$result{$k}{$kk}{good}."/".$result{$k}{$kk}{total}." (".sprintf("%.3f",$result{$k}{$kk}{good}/$result{$k}{$kk}{total}).(($result{$k}{$kk}{good}>0 and $show_z)?"; z=".sprintf("%.3f",$z).(($kk=~/auth/)?"; z_pdns=".sprintf("%.3f",$z2):""):"")."),$success_name{$r}";
		}
		else 
		{
			print ",,";
		}
		if ($in_effect)
		{
			$n++;
		}
	}
	if (not $include_delayed)
	{
		$sigmask&=0x3FFFF;
	}
	print ","; #blank
	print ",$columns,$good_columns,$anom_columns,$num_test".sprintf(",0x%06x",$sigmask).",".($undet?"undetermined":sprintf("0x%06x",$sig));
	my $possible_ns="";
	if (not $undet)
	{
		foreach $ns (sort keys %server_sig)
		{
			if ($detect_pdns and (not $maybe_pdns) and ($ns=~/PowerDNS/))
			{
				next;
			}
			if (($server_sig{$ns}&$sigmask) eq $sig)
			{
				$possible_ns.=$ns."|";
			}
		}
	}
	if ($detect_pdns and $maybe_pdns and $possible_ns=~/PowerDNS/)
	{
		$possible_ns="! PowerDNS|";
	}
	print ",".substr($possible_ns,0,-1);
	
	my $possible_ns_guess="";
	foreach $ns (sort keys %server_sig)
	{
		if ($detect_pdns and (not $maybe_pdns) and ($ns=~/PowerDNS/))
		{
			next;
		}
		if (($server_sig{$ns}&$sigmask) eq $sig_guess)
		{
			$possible_ns_guess.=$ns."|";
		}
	}
	if ($detect_pdns and $maybe_pdns and $possible_ns_guess=~/PowerDNS/)
	{
		$possible_ns_guess="! PowerDNS|";
	}
	print sprintf(",0x%06x",$sig_guess).",".substr($possible_ns_guess,0,-1);
	
	
	my $possible_ns_multimatch="";
	my $sigmask_multimatch=$sigmask&(~0x03c000);  # exlude the hardening tests. Ugly kludge... making sure that hardening is excluded from the main algo.
	foreach $ns1 (sort keys %server_sig)
	{
		foreach $ns2 (sort keys %server_sig)
		{
			next if ($ns2 le $ns1);
			my $x1=$server_sig{$ns1}&$sigmask_multimatch;
			my $x2=$server_sig{$ns2}&$sigmask_multimatch;
			if ((($xor_multiguess&$sigmask_multimatch) eq ($x1^$x2)) and ((($sig_multiguess&$sigmask_multimatch)&(~$xor_multiguess)) eq ($x1&(~$xor_multiguess))))
			{
				my $both_bits=($server_sig{$ns1}&0x03c000) & ($server_sig{$ns2}&0x03c000);
				next if (((($sig_multiguess&0x03c000)) & $both_bits) ne $both_bits);  # Kludge - if the target does use hardening, then ensure that one of the candidate does so too.
				my $no_bits= ~(($server_sig{$ns1}&0x03c000) | ($server_sig{$ns2}&0x03c000));
				next if ((($sig_multiguess&0x03c000) & $no_bits) ne 0);  # Kludge - if the target does use hardening, then ensure that one of the candidate does so too.
				next if ((($sig_multiguess&0x01c000) eq 0) and ((($server_sig{$ns1}&0x01c000) | ($server_sig{$ns2}&0x01c000)) ne 0));   # Super kludge... remove most noise...
				#$possible_ns_multimatch.="($ns1+$ns2 : ".sprintf("nobits=0x%06x sig&m=0x%06x",$no_bits,$sig_multiguess&0x03c000).")|";
				$possible_ns_multimatch.="($ns1+$ns2)|";
			}
		}
	}
	print ",".sprintf("0x%06x",$sig_multiguess).",".sprintf("0x%06x",$xor_multiguess).",".substr($possible_ns_multimatch,0,-1);
	
	my $min_hamming=9999;
	my $possible_ns_hamming="";
	foreach $ns (sort keys %server_sig)
	{
		if ($detect_pdns and (not $maybe_pdns) and ($ns=~/PowerDNS/))
		{
			next;
		}
		my $cur_hamming=hamming(($server_sig{$ns}&$sigmask),$sig_guess);
		if ($cur_hamming<$min_hamming)
		{
			$possible_ns_hamming=$ns."|";
			$min_hamming=$cur_hamming;
		}
		elsif ($cur_hamming eq $min_hamming)
		{
			$possible_ns_hamming.=$ns."|";
		}
	}
	if ($detect_pdns and $maybe_pdns and $possible_ns_guess=~/PowerDNS/)
	{
		$possible_ns_hamming="! PowerDNS|";
	}
	print ",".$min_hamming.",".substr($possible_ns_hamming,0,-1);
	
	
	# FINAL
	print ",".($undet?substr($possible_ns_guess.$possible_ns_multimatch,0,-1):substr($possible_ns,0,-1));
	
	print ",".($use_version?$ver{$ln_num}:"(N/A)");
	
	my $min_port=99999;
	my $max_port=0;
	my %p_seen;
	foreach $p (keys %{$port_stat{$ln}})
	{
		if ($p<$min_port)
		{
			$min_port=$p;
		}
		if ($p>$max_port)
		{
			$max_port=$p;
		}
		$p_seen{$p}++;
	}
	my $port_range=($max_port-$min_port+1);
	my $port_strategy="UNKNOWN";
	if ($port_range==1)
	{
		$port_strategy="Static (#=1)";
	}
	elsif  ((($port_range<=2500) and ($port_range>=2000)) and ($min_port>=49152))
	{
		$port_strategy="MS-DNS-pool (#=2500)";
	}
	elsif (($min_port>=49152) and ($port_range>=10000))
	{
		$port_strategy="Windows/BSD (49152...65535 #=16384)";
	}
	elsif (($min_port>=32768) and ($port_range>=30000))
	{
		$port_strategy="Solaris/AIX (32768...65535 #=32768)";
	}
	elsif (($min_port>=10000) and ($port_range>=50000))
	{
		$port_strategy="FreeBSD (10000...65535 #=55536)";
	}
	elsif (($min_port>=1024) and ($port_range>=60000))
	{
		$port_strategy="UNIX (1024...65535 #=64512)";
	}
	
	print ",$min_port,$max_port,$port_range,$port_strategy,".scalar(keys %p_seen);
	
	my $qid_algo="";
	if (($qid_ln{$ln}{1}>0) and ($qid_ln{$ln}{2}==0))
	{
		$qid_algo="BIND 9.2.3-9.4.1 QID";
	}
	elsif (($qid_ln{$ln}{2}>0) and ($qid_ln{$ln}{1}==0))
	{
		$qid_algo="BIND 9.0.0-9.2.2 QID";
	}
	elsif (($qid_ln{$ln}{1}>0) and ($qid_ln{$ln}{2}>0))
	{
		$qid_algo="Huh?!?!?!";
	}
	elsif ($qid_ln{$ln}{3}>0)
	{
		$qid_algo="BIND 9.x QID";
	}
	
	print ",$qid_algo,",($qid_ln{$ln}{1}+$qid_ln{$ln}{2}+$qid_ln{$ln}{3}).",".($qid_ln{$ln}{0}+$qid_ln{$ln}{1}+$qid_ln{$ln}{2}+$qid_ln{$ln}{3}).",".(($qid_ln{$ln}{0}+$qid_ln{$ln}{1}+$qid_ln{$ln}{2}+$qid_ln{$ln}{3})>0?($qid_ln{$ln}{1}+$qid_ln{$ln}{2}+$qid_ln{$ln}{3})/($qid_ln{$ln}{0}+$qid_ln{$ln}{1}+$qid_ln{$ln}{2}+$qid_ln{$ln}{3}):"");

	my $best_delta=-999999;
	my $best_score=-1;
	my $total_tests=0;
	foreach $delta (keys %{$port_ln{$ln}})
	{	
		$total_tests+=$port_ln{$ln}{$delta};
		if ($port_ln{$ln}{$delta}>$best_score)
		{
			$best_score=$port_ln{$ln}{$delta};
			$best_delta=$delta;
		}
	}
	print ",$best_delta (bucket: +/- $port_bucket_size),$best_score,$total_tests";
	print "\n";
}

exit;

foreach $k (keys %sb_seen)
{
	if (($sb_seen{$k} ne "bs") and ($sb_seen{$k} ne "sb"))
	{
		print "XXX Oops: line $k seen: $sb_seen{$k}\n";
	}
}

foreach $k (keys %sb_decide)
{
	if ($sb_decide{$k} ne 1)
	{
		print "YYY Oops: line $k decision taken $sb_decide{$k} times\n";
	}
}

foreach $k (keys %ever_seen)
{
	if (not defined $ever_reported{$k})
	{
		print "Line $k was seen but never reported\n";
	}
}

my $total_seen=0;
for ($x=1;$x<=1000;$x++)
{
	if ($ever_seen{$x."b"} or $ever_seen{$x."s"})
	{
		$total_seen++;
	}
}
print "\n\n\nTotal seen: $total_seen\n\n\n";


my %count_pop;
print "\n\n\nline,count\n";
foreach $k (keys %name_seen)
{
	print "$k,".scalar(keys %{$name_seen{$k}})."\n";
	$count_pop{scalar(keys %{$name_seen{$k}})}++;
}
print "\n\n\nattack_count,pop_count\n";

my $ct=0;
foreach $k (keys %count_pop)
{
	$ct+=$count_pop{$k};
}

my $sum=0;
foreach $k (sort {$a<=>$b} keys %count_pop)
{
	$sum+=$count_pop{$k};
	print "$k,$sum,".($sum/$ct)."\n";
}
exit;

print "\n\n\n\n\n\n";

foreach $k (sort {$a <=> $b} keys %count_bt_total)
{
	print "$k,$count_bt_total{$k}\n";
}

exit;


foreach $k (sort {$a <=> $b} keys %count_bt)
{
	my $n=0;
	foreach $kk (keys %{$count_bt{$k}})
	{
		$n++;
	}
	print "$k,$n\n";
}

