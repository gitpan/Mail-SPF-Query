
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
BEGIN {

  @test_table = grep { /\S/ and not /^\s*#/ }  split /\n/, q(
2  localhost.localdomain      127.0.0.1           pass

# '01.spf1-test.mailzone.com:v=spf1                                                             :60
# '02.spf1-test.mailzone.com:v=spf1                                             -all       :60
# '03.spf1-test.mailzone.com:v=spf1                                             -all:60
# '04.spf1-test.mailzone.com:v=spf1                                             +all   :60::poboxnet
# '05.spf1-test.mailzone.com:v=spf1                                             default=deny   :60
# '06.spf1-test.mailzone.com:v=spf1                                             ?all :60
# '07.spf1-test.mailzone.com:v=spf2                                             default=bogus   :60

3  01.spf1-test.mailzone.com  192.0.2.1           unknown
4  02.spf1-test.mailzone.com  192.0.2.1           fail
5  03.spf1-test.mailzone.com  192.0.2.1           fail
6  05.spf1-test.mailzone.com  192.0.2.1           fail
7  06.spf1-test.mailzone.com  192.0.2.1           unknown
8  07.spf1-test.mailzone.com  192.0.2.1           unknown
9 808.spf1-test.mailzone.com  192.0.2.1           unknown

# '08.spf1-test.mailzone.com:v=spf1                       -all      -all  :60
# '09.spf1-test.mailzone.com:v=spf1    scope=header-from scope=envelope         -all  :60

# '10.spf1-test.mailzone.com:v=spf1 mx                                          -all:60
10  10.spf1-test.mailzone.com  192.0.2.1           fail
11  10.spf1-test.mailzone.com  192.0.2.10          pass
12  10.spf1-test.mailzone.com  192.0.2.11          pass
13  10.spf1-test.mailzone.com  192.0.2.12          pass
14   10.spf1-test.mailzone.com  192.0.2.13          pass
15   10.spf1-test.mailzone.com  192.0.2.20          pass
16   10.spf1-test.mailzone.com  192.0.2.21          pass
17   10.spf1-test.mailzone.com  192.0.2.22          pass
18   10.spf1-test.mailzone.com  192.0.2.23          pass
19   10.spf1-test.mailzone.com  192.0.2.30          pass
20   10.spf1-test.mailzone.com  192.0.2.31          pass
21   10.spf1-test.mailzone.com  192.0.2.32          pass
22   10.spf1-test.mailzone.com  192.0.2.33          pass
23   10.spf1-test.mailzone.com  192.0.2.34          fail

# @10.spf1-test.mailzone.com::mx01.spf1-test.mailzone.com:10:60
# @10.spf1-test.mailzone.com::mx02.spf1-test.mailzone.com:10:60
# @10.spf1-test.mailzone.com::mx03.spf1-test.mailzone.com:20:60
# 
# @12.spf1-test.mailzone.com::mx01.spf1-test.mailzone.com:10:60
# @12.spf1-test.mailzone.com::mx02.spf1-test.mailzone.com:10:60
# @12.spf1-test.mailzone.com::mx03.spf1-test.mailzone.com:20:60
# 
# @14.spf1-test.mailzone.com::mx01.spf1-test.mailzone.com:10:60
# @14.spf1-test.mailzone.com::mx02.spf1-test.mailzone.com:10:60
# @14.spf1-test.mailzone.com::mx03.spf1-test.mailzone.com:20:60
 
# '11.spf1-test.mailzone.com:v=spf1    mx\072spf1-test.mailzone.com                          -all:60
24   11.spf1-test.mailzone.com  192.0.2.1           fail
25   11.spf1-test.mailzone.com  192.0.2.10          pass
26   11.spf1-test.mailzone.com  192.0.2.33          pass
 
# '12.spf1-test.mailzone.com:v=spf1 mx mx\072spf1-test.mailzone.com                          -all:60
27   12.spf1-test.mailzone.com  192.0.2.1           fail
28   12.spf1-test.mailzone.com  192.0.2.10          pass
29   12.spf1-test.mailzone.com  192.0.2.33          pass
30   12.spf1-test.mailzone.com  208.210.124.192     fail
 
# '13.spf1-test.mailzone.com:v=spf1    mx\072spf1-test.mailzone.com mx\072fallback-relay.spf1-test.mailzone.com -all:60
31   13.spf1-test.mailzone.com  192.0.2.1           fail
32   13.spf1-test.mailzone.com  192.0.2.10          pass
33   13.spf1-test.mailzone.com  192.0.2.33          pass
34   13.spf1-test.mailzone.com  208.210.124.192     fail
35   13.spf1-test.mailzone.com  192.0.2.40          pass
 
# '14.spf1-test.mailzone.com:v=spf1 mx mx\072spf1-test.mailzone.com mx\072fallback-relay.spf1-test.mailzone.com -all:60
36   14.spf1-test.mailzone.com  192.0.2.1           fail
37   14.spf1-test.mailzone.com  192.0.2.10          pass
38   14.spf1-test.mailzone.com  192.0.2.33          pass
39   13.spf1-test.mailzone.com  208.210.124.192     fail
40   13.spf1-test.mailzone.com  192.0.2.40          pass

# # the spf1-test.mailzone.com domain has two A records and three MX records.
# # the first A record has no PTR.  the second does.  it's real.
# @spf1-test.mailzone.com::mx01.spf1-test.mailzone.com:10:60
# @spf1-test.mailzone.com::mx02.spf1-test.mailzone.com:10:60
# @spf1-test.mailzone.com::mx03.spf1-test.mailzone.com:20:60
# 
# +spf1-test.mailzone.com:192.0.2.200:60
# =spf1-test.mailzone.com:208.210.124.192:60
# 
# @fallback-relay.spf1-test.mailzone.com::mx04.spf1-test.mailzone.com:10:60
# 
# +mx01.spf1-test.mailzone.com:192.0.2.10:60
# +mx01.spf1-test.mailzone.com:192.0.2.11:60
# +mx01.spf1-test.mailzone.com:192.0.2.12:60
# +mx01.spf1-test.mailzone.com:192.0.2.13:60
# 
# +mx02.spf1-test.mailzone.com:192.0.2.20:60
# +mx02.spf1-test.mailzone.com:192.0.2.21:60
# +mx02.spf1-test.mailzone.com:192.0.2.22:60
# +mx02.spf1-test.mailzone.com:192.0.2.23:60
# 
# +mx03.spf1-test.mailzone.com:192.0.2.30:60
# +mx03.spf1-test.mailzone.com:192.0.2.31:60
# +mx03.spf1-test.mailzone.com:192.0.2.32:60
# +mx03.spf1-test.mailzone.com:192.0.2.33:60
# 
# +mx04.spf1-test.mailzone.com:192.0.2.40:60
# +mx04.spf1-test.mailzone.com:192.0.2.41:60
# +mx04.spf1-test.mailzone.com:192.0.2.42:60
# +mx04.spf1-test.mailzone.com:192.0.2.43:60
# 

# '20.spf1-test.mailzone.com:v=spf1 a                                           -all:60
41 20.spf1-test.mailzone.com    192.0.2.1           fail
42 20.spf1-test.mailzone.com    192.0.2.120         pass

# '21.spf1-test.mailzone.com:v=spf1   a\072spf1-test.mailzone.com                            -all:60
43 21.spf1-test.mailzone.com    192.0.2.1           fail
44 21.spf1-test.mailzone.com    192.0.2.121         fail
45 21.spf1-test.mailzone.com    192.0.2.200         pass

# '22.spf1-test.mailzone.com:v=spf1 a a\072spf1-test.mailzone.com                            -all:60
46 22.spf1-test.mailzone.com    192.0.2.1           fail
47 22.spf1-test.mailzone.com    192.0.2.122         pass
48 22.spf1-test.mailzone.com    192.0.2.200         pass

# 
# +20.spf1-test.mailzone.com:192.0.2.120:60
# +21.spf1-test.mailzone.com:192.0.2.121:60
# +22.spf1-test.mailzone.com:192.0.2.122:60
# 

# '30.spf1-test.mailzone.com:v=spf1 ptr                                         -all:60
# '30.spf1-test.mailzone.com:v=spf1 ptr                                         default=softdeny:60
49 30.spf1-test.mailzone.com    64.236.24.4         fail
50 30.spf1-test.mailzone.com    208.210.124.130     pass

# '31.spf1-test.mailzone.com:v=spf1     ptr\072spf1-test.mailzone.com                        -all:60
51 31.spf1-test.mailzone.com    64.236.24.4         fail
52 31.spf1-test.mailzone.com    208.210.124.130     pass
53 31.spf1-test.mailzone.com    208.210.124.192     pass

# '32.spf1-test.mailzone.com:v=spf1 ptr ptr\072spf1-test.mailzone.com                        -all:60
54 32.spf1-test.mailzone.com    64.236.24.4         fail
55 32.spf1-test.mailzone.com    208.210.124.130     pass
56 32.spf1-test.mailzone.com    208.210.124.131     pass
57 32.spf1-test.mailzone.com    208.210.124.192     pass

# =30.spf1-test.mailzone.com:208.210.124.130:60
# =31.spf1-test.mailzone.com:208.210.124.131:60
# =32.spf1-test.mailzone.com:208.210.124.132:60

# '40.spf1-test.mailzone.com:v=spf1 exists\072%{ir}.%{v}._spf.%{d}                    -all:60
58 40.spf1-test.mailzone.com    192.0.2.100         pass
59 40.spf1-test.mailzone.com    192.0.2.101         pass
60 40.spf1-test.mailzone.com    192.0.2.102         fail

# '41.spf1-test.mailzone.com:v=spf1 exists\072%{ir}.%{v}._spf.spf1-test.mailzone.com            -all:60
61 41.spf1-test.mailzone.com    192.0.2.100         fail
62 41.spf1-test.mailzone.com    192.0.2.110         pass
63 41.spf1-test.mailzone.com    192.0.2.111         pass

# '42.spf1-test.mailzone.com:v=spf1 exists\072%{ir}.%{v}._spf.%{d} exists\072%{ir}.%{v}._spf.%{d3} -all:60
64 42.spf1-test.mailzone.com    192.0.2.100         fail
65 42.spf1-test.mailzone.com    192.0.2.110         pass
66 42.spf1-test.mailzone.com    192.0.2.130    pass
67 42.spf1-test.mailzone.com    192.0.2.131    pass


# 
# +100.2.0.192.in-addr._spf.40.spf1-test.mailzone.com:127.0.0.2:60
# +101.2.0.192.in-addr._spf.40.spf1-test.mailzone.com:127.0.0.2:60
# 
# +110.2.0.192.in-addr._spf.spf1-test.mailzone.com:127.0.0.2:60
# +111.2.0.192.in-addr._spf.spf1-test.mailzone.com:127.0.0.2:60
# 
# +120.2.0.192.spf1-test.mailzone.com:127.0.0.2:60
# +121.2.0.192.spf1-test.mailzone.com:127.0.0.2:60
# 
# +130.2.0.192.in-addr._spf.42.spf1-test.mailzone.com:127.0.0.2:60
# +131.2.0.192.in-addr._spf.42.spf1-test.mailzone.com:127.0.0.2:60
# 

# '45.spf1-test.mailzone.com:v=spf1 -a a\072spf1-test.mailzone.com                           -all:60
68 45.spf1-test.mailzone.com    192.0.2.140    fail
69 45.spf1-test.mailzone.com    192.0.2.145    fail
70 45.spf1-test.mailzone.com    192.0.2.146    fail
71 45.spf1-test.mailzone.com    192.0.2.147    fail
72 45.spf1-test.mailzone.com    192.0.2.148    fail
73 45.spf1-test.mailzone.com    208.210.124.192    pass
74 45.spf1-test.mailzone.com    192.0.2.200    pass

# 
# +45.spf1-test.mailzone.com:192.0.2.145:60
# +45.spf1-test.mailzone.com:192.0.2.146:60
# +45.spf1-test.mailzone.com:192.0.2.147:60
# 

# '50.spf1-test.mailzone.com:v=spf1 include                                     -all:60
75 50.spf1-test.mailzone.com    192.0.2.200    fail

# '51.spf1-test.mailzone.com:v=spf1 include\07242.spf1-test.mailzone.com                  -all:60
76 51.spf1-test.mailzone.com    192.0.2.200       fail
77 51.spf1-test.mailzone.com    192.0.2.130       pass

# '52.spf1-test.mailzone.com:v=spf1 include\07253.spf1-test.mailzone.com                  -all:60
# C53.spf1-test.mailzone.com:54.spf1-test.mailzone.com
# '54.spf1-test.mailzone.com:v=spf1 include\07242.spf1-test.mailzone.com                  -all:60
78 52.spf1-test.mailzone.com    192.0.2.200       fail
79 52.spf1-test.mailzone.com    192.0.2.130       pass

# '55.spf1-test.mailzone.com:v=spf1 include\07256.spf1-test.mailzone.com                  -all:60
80 55.spf1-test.mailzone.com    192.0.2.200       unknown
81 55.spf1-test.mailzone.com    192.0.2.130       unknown

# SPF1_TEST(56) deliberately left blank
82 56.spf1-test.mailzone.com    192.0.2.200       unknown

# include something that doesn't have SPF records
# '57.spf1-test.mailzone.com:v=spf1 include\072spf1-test.mailzone.com         -all:60
83 57.spf1-test.mailzone.com    192.0.2.200       unknown
84 57.spf1-test.mailzone.com    192.0.2.130       unknown

# loop detection
# '58.spf1-test.mailzone.com:v=spf1 include\07259.spf1-test.mailzone.com                  -all:60
# '59.spf1-test.mailzone.com:v=spf1 include\07258.spf1-test.mailzone.com                  -all:60
85 58.spf1-test.mailzone.com    192.0.2.200       unknown
86 59.spf1-test.mailzone.com    192.0.2.130       unknown

# '70.spf1-test.mailzone.com:v=spf1 exists\072%{lr+=}.lp._spf.spf1-test.mailzone.com -all:60
# 
# +*.bob.lp._spf.spf1-test.mailzone.com:127.0.0.2:60
# +bob.lp._spf.spf1-test.mailzone.com:127.0.0.2:60
# 
# # no entries for joe.

# 'SPF1_TEST(70):v=spf1 exists\072%{lr+=}.lp._spf.spf1-test.mailzone.com -all:60
87 droid@70.spf1-test.mailzone.com  192.0.2.103          fail

88 bob+1@70.spf1-test.mailzone.com  192.0.2.103          pass
89 bob+2@70.spf1-test.mailzone.com  192.0.2.103          pass
90   bob@70.spf1-test.mailzone.com  192.0.2.103          pass
91 joe+1@70.spf1-test.mailzone.com  192.0.2.103          fail
92 joe-2@70.spf1-test.mailzone.com  192.0.2.103          fail
93 moe-1@70.spf1-test.mailzone.com  192.0.2.103          fail

# client should substitute mailer-daemon when no localpart.
94 70.spf1-test.mailzone.com  192.0.2.103                pass

# '80.spf1-test.mailzone.com:v=spf1 a mx exists\072%{ir}.%{v}._spf.80.spf1-test.mailzone.com ptr -all:60
# =80.spf1-test.mailzone.com:208.210.124.180:60
# +80.2.0.192.in-addr._spf.80.spf1-test.mailzone.com:127.0.0.2:60
95 80.spf1-test.mailzone.com    64.236.24.4       fail
96 80.spf1-test.mailzone.com    208.210.124.180       pass
97 80.spf1-test.mailzone.com    192.0.2.80       pass

# '90.spf1-test.mailzone.com:v=spf1  ip4\072192.0.2.128/25 -all:60
98 90.spf1-test.mailzone.com    192.0.2.1       fail
99 90.spf1-test.mailzone.com    192.0.2.127       fail
100 90.spf1-test.mailzone.com    192.0.2.129       pass

# '91.spf1-test.mailzone.com:v=spf1 -ip4\072192.0.2.128/25 ip4\072192.0.2.0/24 -all:60
101 91.spf1-test.mailzone.com    192.168.1.1       fail
102 91.spf1-test.mailzone.com    192.0.2.127       pass
103 91.spf1-test.mailzone.com    192.0.2.129       fail

# '92.spf1-test.mailzone.com:v=spf1 ?ip4\072192.0.2.192/26 ip4\072192.0.2.128/25 -ip4\072192.0.2.0/24 -all:60
104 92.spf1-test.mailzone.com    192.168.2.1       fail
105 92.spf1-test.mailzone.com    192.0.2.1       fail
106 92.spf1-test.mailzone.com    192.0.2.129       pass
107 92.spf1-test.mailzone.com    192.0.2.193       pass

# '95.spf1-test.mailzone.com:v=spf1 exists\072%{p}.whitelist.spf1-test.mailzone.com -all:60
# '96.spf1-test.mailzone.com:v=spf1 -exists\072%{d}.blacklist.spf1-test.mailzone.com -all:60
# '97.spf1-test.mailzone.com:v=spf1 exists\072%{p}.whitelist.spf1-test.mailzone.com -exists\072%{d}.blacklist.spf1-test.mailzone.com -all:60
108 95.spf1-test.mailzone.com  208.210.124.180       pass
109 95.spf1-test.mailzone.com  208.210.124.1       fail
110 96.spf1-test.mailzone.com  192.0.2.193       fail
111 97.spf1-test.mailzone.com  208.210.124.180       pass

# +*.spf1-test.mailzone.com.blacklist.spf1-test.mailzone.com:127.0.0.2:60
# +*.spf1-test.mailzone.com.whitelist.spf1-test.mailzone.com:127.0.0.2:60

# '98.spf1-test.mailzone.com:v=spf1 a/26 mx/26 -all:60
# +98.spf1-test.mailzone.com:192.0.2.98:60
# @98.spf1-test.mailzone.com::80.spf1-test.mailzone.com:10:60
112 98.spf1-test.mailzone.com  192.0.2.1          fail
113 98.spf1-test.mailzone.com  192.0.2.98         pass
114 98.spf1-test.mailzone.com  192.0.2.99         pass
115 98.spf1-test.mailzone.com  208.210.124.180    pass
116 98.spf1-test.mailzone.com  208.210.124.1      fail
117 98.spf1-test.mailzone.com  208.210.124.181    pass

# 'SPF1_TEST(08):v=spf2                       default=softdeny      default=deny  :60
# 'SPF1_TEST(09):v=spf2    scope=header-from scope=envelope         default=deny  :60
118 08.spf1-test.mailzone.com  192.0.2.1     fail
119 09.spf1-test.mailzone.com  192.0.2.1     fail

# '99.spf1-test.mailzone.com:v=spf1 -all exp=99txt.spf1-test.mailzone.com moo:60
# '99txt.spf1-test.mailzone.com:%u %s %d %t %h %i %% %U %S %D %T %H %I %% moo:60
120 99.spf1-test.mailzone.com  192.0.2.1     fail

# testing redirection
# '100.spf1-test.mailzone.com:v=spf1      redirect=98.spf1-test.mailzone.com:60
121 100.spf1-test.mailzone.com  192.0.2.1     fail
122 100.spf1-test.mailzone.com  192.0.2.98    pass

# '101.spf1-test.mailzone.com:v=spf1 -all redirect=98.spf1-test.mailzone.com:60
123 101.spf1-test.mailzone.com  192.0.2.98    fail

# '102.spf1-test.mailzone.com:v=spf1 ?all redirect=98.spf1-test.mailzone.com:60
124 102.spf1-test.mailzone.com  192.0.2.98    pass

# '103.spf1-test.mailzone.com:v=spf1      redirect=98.%{d3}:60
125 103.spf1-test.mailzone.com  192.0.2.98    pass

# '104.spf1-test.mailzone.com:v=spf1      redirect=105.%{d3}:60
# '105.spf1-test.mailzone.com:v=spf1      redirect=106.%{d3}:60
# '106.spf1-test.mailzone.com:v=spf1      redirect=107.%{d3}:60
# '107.spf1-test.mailzone.com:v=spf1       include\072104.%{d3}:60
126,127,128	droid@104.spf1-test.mailzone.com	192.0.2.98	unknown	loop encountered: 104.spf1-test.mailzone.com redirects to 105.spf1-test.mailzone.com redirects to 106.spf1-test.mailzone.com redirects to 107.spf1-test.mailzone.com includes 104.spf1-test.mailzone.com	an error occurred during SPF processing of domain of droid@104.spf1-test.mailzone.com

129,130,131	droid@110.spf1-test.mailzone.com	192.0.2.98	unknown some:unrecognized=mechanism	unrecognized mechanism some	encountered unrecognized mechanism during SPF processing of domain of droid@110.spf1-test.mailzone.com

);

# keep the numbers straight with perl -ple 'BEGIN { $num = 1 } s/(?:^|\G)(\d+)(,)?/++$num . "$2"/eg;'

  plan tests => 1+ @test_table ;
};

use Mail::SPF::Query;

# 1: did the library load okay?
ok(1);

#########################

foreach my $tuple (@test_table) {
  my ($num, $domain, $ipv4, $expected_result, $expected_smtp_comment, $expected_header_comment) = $tuple =~ /\t/ ? split(/\t/, $tuple) : split(' ', $tuple);

  my $sender = $domain;
  if ($domain =~ /\@/) { ($domain) = $domain =~ /\@(.+)/ }

  my ($result, $smtp_comment, $header_comment) = eval  { new Mail::SPF::Query (ipv4   => $ipv4,
									       sender => $sender,
									       helo   => $domain,
									      )->result; };
  $header_comment =~ s/^\S+: //; # strip the reporting hostname prefix

  my $ok = (! $expected_smtp_comment
	    ?  ok($result, $expected_result)
	    : (ok($result, $expected_result) &&
	       ok($smtp_comment, $expected_smtp_comment) &&
	       ok($header_comment, $expected_header_comment)));
  
  if (not $ok) {
    Mail::SPF::Query->clear_cache;
    my $result = eval { scalar(new Mail::SPF::Query (ipv4   => $ipv4,
						     sender => $sender,
						     helo   => $domain,
						     debug  => 1,
						    )->result) };
    if ($@) {
      print "  trapped error: $@\n";
      next;
    }
  }
}

