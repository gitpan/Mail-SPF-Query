
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
BEGIN {

  open TESTFILE, "test.txt";
  @test_table = grep { /\S/ and not /^\s*#/ } <TESTFILE>;
  chomp @test_table;
  close TESTFILE;

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

