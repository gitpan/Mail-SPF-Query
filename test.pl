
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
use strict;

my @test_table;

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

  my ($sender, $localpolicy) = split(':', $domain, 2);
  $sender =~ s/\\([0-7][0-7][0-7])/chr(oct($1))/ge;
  $domain = $sender;
  if ($domain =~ /\@/) { ($domain) = $domain =~ /\@(.+)/ }

  if ($expected_result =~ /=(pass|fail),/) {
      for (my $debug = 0; $debug < 2; $debug++) {
          Mail::SPF::Query->clear_cache;
          my $query = eval  { new Mail::SPF::Query (ipv4   => $ipv4,
                                                    sender => $sender,
                                                    helo   => $domain,
                                                    debug  => $debug,
                                                    local  => $localpolicy,
                                                    sanitize => 1,
                                                   ); };

          my $ok = 1;
          my $header_comment;

          foreach my $e_result (split(/,/, $expected_result)) {
              if ($e_result !~ /=/) {
                  my ($msg_result, $smtp_comment);
                  ($msg_result, $smtp_comment, $header_comment) = eval { $query->message_result2 };

                  $ok = ok($msg_result, $e_result) if (!$debug);
                  if (!$ok) {
                      last;
                  }
              } else {
                  my ($recip, $expected_recip_result) = split(/=/, $e_result, 2);
                  my ($recip_result, $smtp_comment) = eval { $query->result2(split(';',$recip)) };

                  $ok = ok($recip_result, $expected_recip_result) if (!$debug);
                  if (!$ok) {
                      last;
                  }
              }
          }

          $header_comment =~ s/\S+: //; # strip the reporting hostname prefix

          if ($expected_header_comment) {
              $ok &= ok($header_comment, $expected_header_comment) if (!$debug);
          }
          last if ($ok);
      }
  } else {
      my ($result, $smtp_comment, $header_comment) = eval  { new Mail::SPF::Query (ipv4   => $ipv4,
                                                                                   sender => $sender,
                                                                                   helo   => $domain,
                                                                                   local  => $localpolicy,
                                                                                   default_explanation => "explanation",
                                                                                   sanitize => 1,
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
                                                         local  => $localpolicy,
                                                         sanitize => 1,
                                                        )->result) };
        if ($@) {
          print "  trapped error: $@\n";
          next;
        }
      }
  }
}

