
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
BEGIN { plan tests => 6 };
use Mail::SPF::Query;

# 1: did the library load okay?
ok(1);

#########################

# 2: test localhost shortcircuit always-pass
ok(eval { new Mail::SPF::Query (ipv4 => "127.0.0.1", sender => "localhost.localdomain", fallbacks => [])->result },
   "pass");

# 3: mail-spf-test.mailzone.com provides a specific pass for 1.1.1.1
ok(eval { new Mail::SPF::Query (ipv4 => "1.1.1.1", sender => "mail-spf-test.mailzone.com", fallbacks => [])->result },
   "pass");

# 4: mail-spf-test.mailzone.com provides a specific fail for 1.1.1.2
ok(eval { new Mail::SPF::Query (ipv4 => "1.1.1.2", sender => "mail-spf-test.mailzone.com", fallbacks => [])->result },
   "fail");

# 5: unknown.mailzone.com does not exist.
ok(eval { new Mail::SPF::Query (ipv4 => "1.1.1.3", sender => "unknown.mailzone.com", fallbacks => [])->result },
   "unknown");

# 6: test fallbacking.
ok(eval { new Mail::SPF::Query (ipv4 => "1.2.3.4", sender => "mytest.tld", fallbacks => ["fallback.mail-spf-test.mailzone.com"])->result },
   "pass");

