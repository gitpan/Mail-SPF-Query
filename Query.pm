package Mail::SPF::Query;

# ----------------------------------------------------------
# 		       Mail::SPF::Query
#
# 		       Meng Weng Wong
#		  <mengwong+spf@pobox.com>
# $Id: Query.pm,v 1.29 2003/12/17 22:29:25 devel Exp $
# test an IP / sender address pair for pass/fail/nodata/error
#
# http://spf.pobox.com/
#
# this version is compatible with draft-02.9.4.txt
#
# license: opensource.
#
# TODO: add ipv6 support
#
# BUGS:
#  mengwong 20031211
#    if there are multiple unrecognized mechanisms, they all
#    need to be preserved in the 'unknown' Received-SPF header.
#    right now only the first appears.
# ----------------------------------------------------------

use 5.006;
use strict;
use warnings;
no warnings 'uninitialized';
use vars qw($VERSION $CACHE_TIMEOUT);

use URI::Escape;
use Net::CIDR::Lite;
use Net::DNS qw(); # by default it exports mx, which we define.

use Sys::Hostname;
eval { require Sys::Hostname::Long }; my $HOSTNAME = $@ ? hostname() : Sys::Hostname::Long::hostname_long();

# ----------------------------------------------------------
# 		       initialization
# ----------------------------------------------------------

my $GUESS_MECHS = "a/24 mx/24 ptr exists:%{p}.wl.trusted-forwarder.org exists:%{ir}.wl.trusted-forwarder.org";

my @KNOWN_MECHANISMS = qw( a mx ptr include ip4 ip6 exists all );

my $MAX_RECURSION_DEPTH = 10;

my $Domains_Queried = {};

$VERSION = "1.9.6";

$CACHE_TIMEOUT = 120;

# ----------------------------------------------------------
# 	 no user-serviceable parts below this line
# ----------------------------------------------------------

my $looks_like_ipv4  = qr/\d+\.\d+\.\d+\.\d+/;
my $looks_like_email = qr/\S+\@\S+/;

=head1 NAME

Mail::SPF::Query - query Sender Permitted From for an IP,email,helo

=head1 SYNOPSIS

  my $query = new Mail::SPF::Query (ip => "127.0.0.1", sender=>'foo@example.com', helo=>"somehost.example.com");
  my ($result, $smtp_comment, $header_comment) = $query->result();
  my ($guess,  $smtp_guess,   $header_guess)   = $query->best_guess();

  if    ($result eq "pass")     { ... } # domain is not forged
  elsif ($result eq "fail")     { ... } # domain is forged
  else                          {       # domain has not implemented SPF
    if    ($guess eq "pass")    { ... } # result based on $guess_mechs
    elsif ($guess eq "fail")    { ... } # result based on $guess_mechs
    else                        { ... } #
  }

  The default $guess_mechs is "a/24 mx/24 ptr
         exists:%{p}.wl.trusted-forwarder.org
         exists:%{ir}.wl.trusted-forwarder.org".

=head1 ABSTRACT

The SPF protocol relies on sender domains to publish a DNS
whitelist of their designated outbound mailers.  Given an
envelope sender, Mail::SPF::Query determines the legitimacy
of an SMTP client IP.

=head1 METHODS

=head2 Mail::SPF::Query->new()

  my $query = eval { new Mail::SPF::Query (ip    =>"127.0.0.1",
                                           sender=>'foo@example.com',
                                           helo  =>"host.example.com") };

  optional parameters:
     guess_mechs => "a/24 mx/24 ptr exists:%{p}.wl.trusted-forwarder.org",
     debug => 1, debuglog => sub { print STDERR "@_\n" },
     max_recursion_depth => 10,

  if ($@) { warn "bad input to Mail::SPF::Query: $@" }

Set C<debug=E<gt>1> to watch the queries happen.

=cut

# ----------------------------------------------------------
sub new {
# ----------------------------------------------------------
  my $class = shift;
  my $query = bless { guess_mechs => $GUESS_MECHS,
		      depth => 0,
		      @_,
		    }, $class;

  $query->{ipv4} = delete $query->{ip}   if $query->{ip}   and $query->{ip} =~ $looks_like_ipv4;
  $query->{helo} = delete $query->{ehlo} if $query->{ehlo};

  $query->{sender} =~ s/<(.*)>/$1/g;

  if (not ($query->{ipv4}   and length $query->{ipv4}))   { die "no IP address given to spfquery"   }

  for ($query->{sender}) { s/^\s+//; s/\s+$//; }

  ($query->{domain}) = $query->{sender} =~ /([^@]+)$/; # given foo@bar@baz.com, the domain is baz.com, not bar@baz.com.

  if (not $query->{helo}) { require Carp; import Carp qw(cluck); cluck ("Mail::SPF::Query: ->new() requires a \"helo\" argument.\n");
			    $query->{helo} = $query->{domain};
			  }

  $query->debuglog("new: ipv4=$query->{ipv4}, sender=$query->{sender}, helo=$query->{helo}");

  ($query->{helo}) =~ s/.*\@//; # strip localpart from helo

  if (not $query->{domain}) {
    $query->debuglog("spfquery: sender $query->{sender} has no domain, using HELO domain $query->{helo} instead.");
    $query->{domain} = $query->{helo};
    $query->{sender} = $query->{helo};
  }

  if (not length $query->{domain}) { die "unable to identify domain of sender $query->{sender}" }

  $query->{orig_domain} = $query->{domain};

  $query->{loop_report} = [$query->{domain}];

  ($query->{localpart}) = $query->{sender} =~ /(.+)\@/;
  $query->{localpart} = "postmaster" if not length $query->{localpart};

  $query->debuglog("localpart is $query->{localpart}");

  $query->{Reversed_IP} = ($query->{ipv4} ? reverse_in_addr($query->{ipv4}) :
			   $query->{ipv6} ? die "IPv6 not supported" : "");

  $query->post_new(@_) if $class->can("post_new");

  return $query;
}

=head2 $query->result()

  my ($result, $smtp_comment, $header_comment) = $query->result();

C<$result> will be one of C<pass>, C<fail>, C<unknown>, or C<error>.

C<pass> means the client IP is a designated mailer for the
sender.  The mail should be accepted subject to local policy
regarding the sender.

C<fail> means the client IP is not a designated mailer, and
the sender wants you to reject the transaction for fear of
forgery.

C<unknown> means the domain either does not publish SPF data
or has a configuration error in the published data.

C<error> means the DNS lookup encountered a temporary error
during processing.

Results are cached internally for a default of 120 seconds.
You can call C<-E<gt>result()> repeatedly; subsequent
lookups won't hit your DNS.

The smtp_comment should be displayed to the SMTP client.

The header_comment goes into a Received-SPF header.

=cut

# ----------------------------------------------------------
#			    result
# ----------------------------------------------------------

sub result {
  my $query = shift;
  my %result_set;

  my ($result, $smtp_comment) = $query->spfquery();

  # print STDERR "*** result = $result\n";

  if ($result eq "fail") {
    my $receiver = uri_escape($HOSTNAME);
    my $why_url = $query->macro_substitute("http://spf.pobox.com/why.html?sender=%{S}&ip=%{I}&receiver=$receiver");
    $smtp_comment ||= "please see $why_url";
  }

  $query->{smtp_comment} = $smtp_comment;

  return (lc $result,
	  $smtp_comment,
	  "$HOSTNAME: ". $query->header_comment($result)) if wantarray;

  return  lc $result;
}

sub header_comment {
  my $query = shift;
  my $result = shift;
  my $ip = $query->ip;
  if ($result eq "pass" and $query->{smtp_comment} eq "localhost is always allowed.") { return $query->{smtp_comment} }

  return
    (  $result eq "pass"     ? "domain of $query->{sender} designates $ip as permitted sender"
     : $result eq "fail"     ? "domain of $query->{sender} does not designate $ip as permitted sender"
     : $result eq "softfail" ? "transitioning domain of $query->{sender} does not designate $ip as permitted sender"
     : $result eq "error"    ? "error in processing during lookup of $query->{sender}"
     : $result eq "UNKNOWN"  ? "unable to determine SPF status for $query->{sender}"
     : $result =~ /^UNKNOWN/ ? "encountered unrecognized mechanism during SPF processing of domain of $query->{sender}"
     :                         "domain of $query->{sender} does not designate permitted sender hosts" );

}

=head2 $query->best_guess()

  my ($result, $smtp_comment, $header_comment) = $query->best_guess();

When a domain does not publish SPF records, this library can
produce an educated guess anyway.

It pretends the domain defined A, MX, and PTR mechanisms,
plus a few others.  The default set of directives is

  "a/24 mx/24 pt rexists:%{p}.wl.trusted-forwarder.org exists:%{ir}.wl.trusted-forwarder.org"

That default set will return either "pass" or "unknown".

=cut

sub clone {
  my $query = shift;
  my $class = ref $query;

  my %guts = (%$query, @_, parent=>$query);

  my $clone = bless \%guts, $class;

  push @{$clone->{loop_report}}, delete $clone->{reason};

  $query->debuglog("  clone: new object:");
  for ($clone->show) { $clone->debuglog( "clone: $_" ) }

  return $clone;
}

sub top {
  my $query = shift;
  if ($query->{parent}) { return $query->{parent}->top }
  return $query;
}

sub set_error {
  my $query = shift;
  $query->{error} = shift;
}

sub show {
  my $query = shift;

  return map { sprintf ("%20s = %s", $_, $query->{$_}) } keys %$query;
}

sub best_guess {
  my $query = shift;

  # clone the query object with best_guess mode turned on.
  my $guess_query = $query->clone( best_guess => 1,
				   reason => "has no data.  best guess",
				 );

  $guess_query->{depth} = 0;

  # if result is not defined, the domain has no SPF.
  #    perform fallback lookups.
  #    perform trusted-forwarder lookups.
  #    perform guess lookups.
  #
  # if result is defined, return it.

  my ($result, $smtp_comment, $header_comment) = $guess_query->result();
  if (defined $result and $result eq "pass") {
    my $ip = $query->ip;
    $header_comment = "seems reasonable for $query->{sender} to mail through $ip";
    return ($result, $smtp_comment, $header_comment) if wantarray;
    return $result;
  }

  return "unknown";
}

# ----------------------------------------------------------

=head2 $query->debuglog()

  Subclasses may override this with their own debug logger.
  I recommend Log::Dispatch.

  Alternatively, pass the C<new()> constructor a
  C<debuglog => sub { ... }> callback, and we'll pass
  debugging lines to that.

=cut

sub debuglog {
  my $self = shift;
  return if ref $self and not $self->{debug};
  
  my $toprint = join (" ", @_);
  chomp $toprint;
  $toprint = sprintf ("%-8s %s %s %s",
		      ("|" x ($self->{depth}+1)),
		      $self->{localpart},
		      $self->{domain},
		      $toprint);

  if (exists $self->{debuglog} and ref $self->{debuglog} eq "CODE") { eval { $self->{debuglog}->($toprint) } ; }
  else { printf STDERR "%s", "$toprint\n"; }
}

# ----------------------------------------------------------
#			    spfquery
# ----------------------------------------------------------

sub spfquery {
  #
  # usage: my ($result, $text, $time) = $query->spfquery()
  #
  #  performs a full SPF resolution using the data in $query.  to use different data, clone the object.
  #
  my $query = shift;

  if ($query->{ipv4} and
      $query->{ipv4}=~ /^127\./) { return "pass", "localhost is always allowed." }

  if ($query->is_looping)            { return "UNKNOWN", $query->is_looping }
  if ($query->can_use_cached_result) { return $query->cached_result; }
  else                               { $query->tell_cache_that_lookup_is_underway; }

  my $directive_set = DirectiveSet->new($query->{domain}, $query);

  if (not defined $directive_set) {
    $query->debuglog("no SPF record found for $query->{domain}");
    $query->delete_cache_point;
    return "unknown", "domain of sender $query->{sender} does not designate mailers";
  }

  if ($directive_set->{hard_syntax_error}) {
    $query->debuglog("  syntax error while parsing $directive_set->{txt}");
    $query->delete_cache_point;
    return "unknown", $directive_set->{hard_syntax_error};
  }

  $query->{directive_set} = $directive_set;

  foreach my $mechanism ($directive_set->mechanisms) {
    my ($result, $comment) = $query->evaluate_mechanism($mechanism);

    if ($query->{error}) {
      $query->debuglog("  returning fatal error: $query->{error}");
      $query->delete_cache_point;
      return "error", $query->{error};
    }

    next if not defined $result;
    if ($result and $result !~ /^unknown/) {
      $query->debuglog("  saving result $result to cache point and returning.");
      $query->save_result_to_cache($result, $comment);
      return $result, $query->interpolate_explanation($comment);
    }
  }

  # run the redirect modifier
  if ($query->{directive_set}->redirect) {
    my $new_domain = $query->macro_substitute($query->{directive_set}->redirect);

    $query->debuglog("  executing redirect=$new_domain");

    my $inner_query = $query->clone(domain => $new_domain,
				    depth  => $query->{depth} + 1,
				    reason => "redirects to $new_domain",
				   );

    my @inner_result = $inner_query->spfquery();

    $query->delete_cache_point;

    $query->debuglog("  executed redirect=$new_domain, got result @inner_result");

    return @inner_result;
  }

  $query->debuglog("  mechanisms returned unknown; deleting cache point and using unknown");
  $query->delete_cache_point;
  return "unknown", $directive_set->{soft_syntax_error} || $query->interpolate_explanation();
}

# ----------------------------------------------------------
# 	      we cache into $Domains_Queried.
# ----------------------------------------------------------

sub cache_point {
  my $query = shift;
  return my $cache_point = join "/", ($query->{best_guess} || 0,
				      $query->{ipv4},
				      $query->{localpart},
				      $query->{domain});
}

sub is_looping {
  my $query = shift;
  my $cache_point = $query->cache_point;
  return (join " ", "loop encountered:", @{$query->{loop_report}})
    if (exists $Domains_Queried->{$cache_point}
	and
	not defined $Domains_Queried->{$cache_point}->[0]);

  return (join " ", "exceeded maximum recursion depth:", @{$query->{loop_report}})
    if ($query->{depth} >= $query->max_recursion_depth);

  return 0;
}

sub max_recursion_depth {
  my $query = shift;
  return $query->{max_recursion_depth} || $MAX_RECURSION_DEPTH;
}

sub can_use_cached_result {
  my $query = shift;
  my $cache_point = $query->cache_point;

  if ($Domains_Queried->{$cache_point}) {
    $query->debuglog("  lookup: we have already processed $query->{domain} before with $query->{ipv4}.");
    my @cached = @{ $Domains_Queried->{$cache_point} };
    if (not defined $CACHE_TIMEOUT
	or time - $cached[2] > $CACHE_TIMEOUT) {
      $query->debuglog("  lookup: but its cache entry is stale; deleting it.");
      delete $Domains_Queried->{$cache_point};
      return 0;
    }

    $query->debuglog("  lookup: the cache entry is fresh; returning it.");
    return 1;
  }
  return 0;
}

sub tell_cache_that_lookup_is_underway {
  my $query = shift;

  # define an entry here so we don't loop endlessly in an Include loop.
  $Domains_Queried->{$query->cache_point} = [undef, undef, time];
}

sub save_result_to_cache {
  my $query = shift;
  my ($result, $comment) = (shift, shift);

  # define an entry here so we don't loop endlessly in an Include loop.
  $Domains_Queried->{$query->cache_point} = [$result, $comment, time];
}

sub cached_result {
  my $query = shift;
  my $cache_point = $query->cache_point;

  if ($Domains_Queried->{$cache_point}) {
    return @{ $Domains_Queried->{$cache_point} };
  }
  return;
}

sub delete_cache_point {
  my $query = shift;
  delete $Domains_Queried->{$query->cache_point};
}

sub clear_cache {
  $Domains_Queried = {};
}

sub get_ptr_domain {
    my ($query) = shift;

    return $query->{ptr_domain} if ($query->{ptr_domain});
    
    foreach my $ptrdname ($query->myquery(reverse_in_addr($query->{ipv4}) . ".in-addr.arpa", "PTR", "ptrdname")) {
        $query->debuglog("  get_ptr_domain: $query->{ipv4} is $ptrdname");
    
        $query->debuglog("  get_ptr_domain: checking hostname $ptrdname for legitimacy.");
    
        # check for legitimacy --- PTR -> hostname A -> PTR
        foreach my $ptr_to_a ($query->myquery($ptrdname, "A", "address")) {
          
            $query->debuglog("  get_ptr_domain: hostname $ptrdname -> $ptr_to_a");
      
            if ($ptr_to_a eq $query->{ipv4}) {
                return $query->{ptr_domain} = $ptrdname;
            }
        }
    }

    return undef;
}

sub macro_substitute_item {
    my $query = shift;
    my $arg = shift;

    if ($arg eq "%") { return "%" }
    if ($arg eq "_") { return " " }
    if ($arg eq "-") { return "%20" }

    $arg =~ s/^{(.*)}$/$1/;

    my ($field, $num, $reverse, $delim) = $arg =~ /^(\w)(\d*)(r?)(.*)$/;

    $delim = '.' if not length $delim;

    my $newval = $arg;
    my $timestamp = time;

    $newval = $query->{localpart}       if (lc $field eq 'u');
    $newval = $query->{localpart}       if (lc $field eq 'l');
    $newval = $query->{domain}          if (lc $field eq 'd');
    $newval = $query->{sender}          if (lc $field eq 's');
    $newval = $query->{orig_domain}     if (lc $field eq 'o');
    $newval = $query->ip                if (lc $field eq 'i');
    $newval = $timestamp                if (lc $field eq 't');
    $newval = $query->{helo}            if (lc $field eq 'h');
    $newval = $query->get_ptr_domain    if (lc $field eq 'p');
    $newval = $query->{ipv4} ? 'in-addr' : 'ip6'
                                        if (lc $field eq 'v');

    # perl has a few rules about where ] and - may fall inside a character class.
    if ($delim =~ s/_//g)  { $delim .= "-" }
    if ($delim =~ s/\]//g) { $delim = "]$delim" }

    if ($reverse) {
      my @parts = split /[$delim]/, $newval;
      $newval = join ".", reverse @parts;
    }

    if ($num) {
      my @parts = split /[$delim]/, $newval;
      while (@parts > $num) { shift @parts }
      $newval = join ".", @parts;
    }

    $newval = uri_escape($newval)       if ($field eq uc $field);

    $query->debuglog("  macro_substitute_item: $arg: field=$field, num=$num, reverse=$reverse, delim=$delim, newval=$newval");

    return $newval;
}

sub macro_substitute {
    my $query = shift;
    my $arg = shift;
    my $maxlen = shift;

    my $original = $arg;

#      macro-char   = ( '%{' alpha *digit [ 'r' ] *delim '}' )
#                     / '%%'
#                     / '%_'
#                     / '%-'

    $arg =~ s/%([%_-]|{(\w[^}]*)})/$query->macro_substitute_item($1)/ge;

    if ($maxlen && length $arg > $maxlen) {
      $arg = substr($arg, -$maxlen);  # super.long.string -> er.long.string
      $arg =~ s/[^.]*\.//;            #    er.long.string ->    long.string
    }
    $query->debuglog("  macro_substitute: $original -> $arg") if ($original ne $arg);
    return $arg;
}

# ----------------------------------------------------------
#		     evaluate_mechanism
# ----------------------------------------------------------

sub evaluate_mechanism {
  my $query = shift;
  my ($modifier, $mechanism, $argument) = @{shift()};

  $modifier = "+" if not length $modifier;

  $query->debuglog("  evaluate_mechanism: $modifier$mechanism($argument) for domain=$query->{domain}");

  if ({ map { $_=>1 } @KNOWN_MECHANISMS }->{$mechanism}) {
    my $mech_sub = "mech_$mechanism";
    my ($hit, $text) = $query->$mech_sub($query->macro_substitute($argument, 255));
    no warnings 'uninitialized';
    $query->debuglog("  evaluate_mechanism: $modifier$mechanism($argument) returned $hit $text");

    return if not $hit;

    return ($hit, $text) if ($hit ne "hit");

    return $query->shorthand2value($modifier), $text;
  }
  else {
    $query->debuglog("  evaluate_mechanism: unrecognized mechanism $mechanism, returning unknown.");
    my $unknown_string = join ("",
			       "UNKNOWN",
			       " ",
			       ($modifier eq "+" ? "" : $modifier),
			       $mechanism,
			       ($argument ? ":" : ""),
			       $argument);
    return $unknown_string => "unrecognized mechanism $mechanism";
    return undef;
  }

  return ("unknown", "evaluate-mechanism: unknown");
}

# ----------------------------------------------------------
# 	     myquery wraps DNS resolver queries
#
# ----------------------------------------------------------

sub myquery {
  my $query = shift;
  my $label = shift;
  my $qtype = shift;
  my $method = shift;
  my $sortby = shift;

  $query->debuglog("  myquery: doing $qtype query on $label");

  for ($label) {
    if (/\.\./ or /^\./) {
      # convert .foo..com to foo.com, etc.
      $query->debuglog("  myquery: fixing up invalid syntax in $label");
      s/\.\.+/\./g;
      s/^\.//;
      $query->debuglog("  myquery: corrected label is $label");
    }
  }
  my $resquery = $query->resolver->query($label, $qtype);

  my $errorstring = $query->resolver->errorstring;
  if (not $resquery and $errorstring eq "NOERROR") {
    return;
  }

  if (not $resquery) {
    if ($errorstring eq "NXDOMAIN") {
      $query->debuglog("  myquery: $label $qtype failed: NXDOMAIN.");
      return;
    }

    $query->debuglog("  myquery: $label $qtype lookup error: $errorstring");
    $query->debuglog("  myquery: will set top-level error condition.");
    $query->top->set_error("DNS error while looking up $label $qtype: $errorstring");
    return;
  }

  my @answers = grep { lc $_->type eq lc $qtype } $resquery->answer;

  # $query->debuglog("  myquery: found $qtype response: @answers");

  my @toreturn;
  if ($sortby) { @toreturn = map { $_->$method() } sort { $a->$sortby() <=> $b->$sortby() } @answers; }
  else         { @toreturn = map { $_->$method() }                                          @answers; }

  if (not @toreturn) {
    $query->debuglog("  myquery: result had no data.");
    return;
  }

  return @toreturn;
}

# ----------------------------------------------------------
# 			    all
# ----------------------------------------------------------

sub mech_all {
  my $query = shift;
  return "hit";
}

# ----------------------------------------------------------
#			  include
# ----------------------------------------------------------

sub mech_include {
  my $query = shift;
  my $argument = shift;

  if (not $argument) {
    $query->debuglog("  mechanism include: no argument given.");
    return "unknown", "include mechanism not given an argument";
  }

  $query->debuglog("  mechanism include: recursing into $argument");

  my $inner_query = $query->clone(domain => $argument,
				  depth  => $query->{depth} + 1,
				  reason => "includes $argument",
				 );

  my ($result, $text, $time) = $inner_query->spfquery();

  $query->debuglog("  mechanism include: got back result $result / $text / $time");

  if (   $result eq "pass")    { return hit     => $text, $time; }
  if (   $result eq "error")   { return error   => $text, $time; }
  if (lc $result eq "unknown") { return UNKNOWN => $text, $time; }
  
  $query->debuglog("  mechanism include: reducing result $result to unknown");
  return "unknown", $text, $time;
}

# ----------------------------------------------------------
# 			     a
# ----------------------------------------------------------

sub mech_a {
  my $query = shift;
  my $argument = shift;
  
  my $ip4_cidr_length = ($argument =~ s/  \/(\d+)//x) ? $1 : 32;
  my $ip6_cidr_length = ($argument =~ s/\/\/(\d+)//x) ? $1 : 128;

  my $domain_to_use = $argument || $query->{domain};

  # see code below in ip4
  foreach my $a ($query->myquery($domain_to_use, "A", "address")) {
    $query->debuglog("  mechanism a: $a");
    if ($a eq $query->{ipv4}) {
      $query->debuglog("  mechanism a: match found: $domain_to_use A $a == $query->{ipv4}");
      return "hit", "$domain_to_use A $query->{ipv4}";
    }
    elsif ($ip4_cidr_length < 32) {
      my $cidr = Net::CIDR::Lite->new("$a/$ip4_cidr_length");

      $query->debuglog("  mechanism a: looking for $query->{ipv4} in $a/$ip4_cidr_length");
      
      return (hit => "$domain_to_use A $a /$ip4_cidr_length contains $query->{ipv4}")
	if $cidr->find($query->{ipv4});
    }
  }
  return;
}

# ----------------------------------------------------------
# 			     mx
# ----------------------------------------------------------

sub mech_mx {
  my $query = shift;
  my $argument = shift;

  my $ip4_cidr_length = ($argument =~ s/  \/(\d+)//x) ? $1 : 32;
  my $ip6_cidr_length = ($argument =~ s/\/\/(\d+)//x) ? $1 : 128;

  my $domain_to_use = $argument || $query->{domain};

  my @mxes = $query->myquery($domain_to_use, "MX", "exchange", "preference");

  # if a domain has no MX record, we MUST NOT use its IP address instead.
  # if (! @mxes) {
  #   $query->debuglog("  mechanism mx: no MX found for $domain_to_use.  Will pretend it is its own MX, and test its IP address.");
  #   @mxes = ($domain_to_use);
  # }

  foreach my $mx (@mxes) {
    # $query->debuglog("  mechanism mx: $mx");

    foreach my $a ($query->myquery($mx, "A", "address")) {
      if ($a eq $query->{ipv4}) {
	$query->debuglog("  mechanism mx: we have a match; $domain_to_use MX $mx A $a == $query->{ipv4}");
	return "hit", "$domain_to_use MX $mx A $a";
      }
      elsif ($ip4_cidr_length < 32) {
	my $cidr = Net::CIDR::Lite->new("$a/$ip4_cidr_length");

	$query->debuglog("  mechanism mx: looking for $query->{ipv4} in $a/$ip4_cidr_length");

	return (hit => "$domain_to_use MX $mx A $a /$ip4_cidr_length contains $query->{ipv4}")
	  if $cidr->find($query->{ipv4});

      }
    }
  }
  return;
}

# ----------------------------------------------------------
# 			    ptr
# ----------------------------------------------------------

sub mech_ptr {
  my $query = shift;
  my $argument = shift;

  if ($query->{ipv6}) { return "unknown", "ipv6 not yet supported"; }

  my $domain_to_use = $argument || $query->{domain};

  foreach my $ptrdname ($query->myquery(reverse_in_addr($query->{ipv4}) . ".in-addr.arpa", "PTR", "ptrdname")) {
    $query->debuglog("  mechanism ptr: $query->{ipv4} is $ptrdname");
    
    $query->debuglog("  mechanism ptr: checking hostname $ptrdname for legitimacy.");
    
    # check for legitimacy --- PTR -> hostname A -> PTR
    foreach my $ptr_to_a ($query->myquery($ptrdname, "A", "address")) {
      
      $query->debuglog("  mechanism ptr: hostname $ptrdname -> $ptr_to_a");
      
      if ($ptr_to_a eq $query->{ipv4}) {
	$query->debuglog("  mechanism ptr: we have a valid PTR: $query->{ipv4} PTR $ptrdname A $ptr_to_a");
	$query->debuglog("  mechanism ptr: now we see if $ptrdname ends in $domain_to_use.");
	
	if ($ptrdname =~ /(^|\.)\Q$domain_to_use\E$/i) {
	  $query->debuglog("  mechanism ptr: $query->{ipv4} PTR $ptrdname does end in $domain_to_use.");
	  return hit => "$query->{ipv4} PTR $ptrdname matches $domain_to_use";
	}
	else {
	  $query->debuglog("  mechanism ptr: $ptrdname does not end in $domain_to_use.  no match.");
	}
      }
    }
  }
  return;
}

# ----------------------------------------------------------
# 			     exists
# ----------------------------------------------------------

sub mech_exists {
  my $query = shift;
  my $argument = shift;

  return if (!$argument);

  my $domain_to_use = $argument;

  $query->debuglog("  mechanism exists: looking up $domain_to_use");
  
  foreach ($query->myquery($domain_to_use, "A", "address")) {
    $query->debuglog("  mechanism exists: $_");
    $query->debuglog("  mechanism exists: we have a match.");
    return hit => "$domain_to_use found";
  }
  return;
}

# ----------------------------------------------------------
# 			    ip4
# ----------------------------------------------------------

sub mech_ip4 {
  my $query = shift;
  my $cidr_spec = shift;

  return if not length $cidr_spec;

  my $cidr = Net::CIDR::Lite->new($cidr_spec); # TODO: sanity check input, make this work for ipv6 as well

  $query->debuglog("  mechanism ip4: looking for $query->{ipv4} in $cidr_spec");

  return (hit => "$cidr_spec contains $query->{ipv4}") if $cidr->find($query->{ipv4});

  return;
}

# ----------------------------------------------------------
# 			    ip6
# ----------------------------------------------------------

sub mech_ip6 {
  my $query = shift;

  return;
}

# ----------------------------------------------------------
# 			 functions
# ----------------------------------------------------------

sub ip { # accessor
  my $query = shift;
  return $query->{ipv4} || $query->{ipv6};
}

sub reverse_in_addr {
  return join (".", (reverse split /\./, shift));
}

sub resolver {
  my $query = shift;
  return $query->{res} ||= Net::DNS::Resolver->new;
}

sub fallbacks {
  my $query = shift;
  return @{$query->{fallbacks}};
}

sub shorthand2value {
  my $query = shift;
  my $shorthand = shift;
  return { "-" => "fail",
	   "+" => "pass",
	   "~" => "UNKNOWN",
	   "?" => "UNKNOWN" } -> {$shorthand} || $shorthand;
}

sub value2shorthand {
  my $query = shift;
  my $value = lc shift;
  return { "fail"     => "-",
	   "pass"     => "+",
	   "softfail" => "~",
	   "deny"     => "-",
	   "allow"    => "+",
	   "softdeny" => "~",
	   "unknown"  => "?" } -> {$value} || $value;
}

sub interpolate_explanation {
  my $query = shift;
  my $comment = shift;

  my $exp;
  if ($query->{directive_set}->explanation) {
    my @txt = map { s/^"//; s/"$//; $_ } $query->myquery($query->macro_substitute($query->{directive_set}->explanation), "TXT", "txtdata");
    $exp = $query->macro_substitute(join " ", @txt);
  }

  if (not $exp) { return $comment }
  if (not $comment) { return $exp }

  return "$exp: $comment";
}

# ----------------------------------------------------------
# 		      algo
# ----------------------------------------------------------

{
  package DirectiveSet;

  sub new {
    my $class = shift;
    my $current_domain = shift;
    my $query = shift;

    my $txt;

    if ($query->{best_guess}) {
      $txt = "v=spf1 $query->{guess_mechs} ?all";
    }
    else {
      $query->debuglog("  DirectiveSet->new(): doing TXT query on $current_domain");
      my @txt = $query->myquery($current_domain, "TXT", "txtdata");

      # squish multiline responses into one first.

      foreach (@txt) {
	s/^"(.*)"$/$1/;
	s/^\s+//;
	s/\s+$//;
	
	if (/^v=spf1(\s.*)/i) {
	  $txt .= $1;
	}
      }
    }

    $query->debuglog("  DirectiveSet->new(): SPF policy: $txt");

    return if not $txt;

    my $directive_set = bless { orig_txt => $txt, txt => $txt } , $class;

    TXT_RESPONSE:
    for ($txt) {
      $query->debuglog("  lookup:   TXT $_");

      # parse the policy record
      
      while (/\S/) {
	s/^\s*(\S+)\s*//;
	my $word = $1;
	# $query->debuglog("  lookup:  word parsing word $word");
	if ($word =~ /^v=(\S+)/i) {
	  my $version = $1;
	  $query->debuglog("  lookup:   TXT version=$version");
	  $directive_set->{version} = $version;
	  next TXT_RESPONSE if ($version ne "spf1");
	  next;
	}

	# modifiers always have an = sign.
	if (my ($lhs, $rhs) = $word =~ /^([^:\/]+)=(\S*)$/) {
	  # $query->debuglog("  lookup:   TXT modifier found: $lhs = $rhs");

	  $directive_set->{modifiers}->{lc $lhs} = $rhs;
	  next;
	}

	# RHS optional, defaults to domain.
	# [:/] matches a:foo and a/24
	if (my ($prefix, $lhs, $rhs) = $word =~ /^([-~+?]?)([\w_-]+)([\/:]\S*)?$/i) {
	  $rhs =~ s/^://;
	  $prefix ||= "+";
	  $prefix = "?" if $prefix eq "~"; # softfail is deprecated, has become "unknown"
	  $query->debuglog("  lookup:   TXT prefix=$prefix, lhs=$lhs, rhs=$rhs");
	  push @{$directive_set->{mechanisms}}, [$prefix => lc $lhs => $rhs];
	  next;
	}

      }
    }

    if (my $rhs = delete $directive_set->{modifiers}->{default}) {
      push @{$directive_set->{mechanisms}}, [ $query->value2shorthand($rhs), all => undef ];
    }

    $directive_set->{mechanisms} = []           if not $directive_set->{mechanisms};
    $query->debuglog("  lookup:  mec mechanisms=@{[$directive_set->show_mechanisms]}");
    return $directive_set;
  }

  sub version      {   shift->{version}      }
  sub mechanisms   { @{shift->{mechanisms}}  }
  sub explanation  {   shift->{modifiers}->{exp}      }
  sub redirect     {   shift->{modifiers}->{redirect} }
  sub get_modifier {   shift->{modifiers}->{shift()}  }
  sub syntax_error {   shift->{syntax_error} }

  sub show_mechanisms   {
    my $directive_set = shift;
    return map { $_->[0] . $_->[1] . "(" . ($_->[2]||"") . ")" } $directive_set->mechanisms;
  }
}

1;

=head2 EXPORT

None by default.

=head1 AUTHOR

Meng Weng Wong, <mengwong+spf@pobox.com>

=head1 SEE ALSO

http://spf.pobox.com/

=cut

