package Mail::SPF::Query;

# ----------------------------------------------------------
# 		       Mail::SPF::Query
#
# 		       Meng Weng Wong
#		  <mengwong+spf@pobox.com>
# $Id: Query.pm,v 1.2 2003/06/26 03:00:21 devel Exp $
# test an IP / sender address pair for pass/fail/nodata/error
#
# license: opensource.
#
# TODO: add ipv6 support
# ----------------------------------------------------------

use 5.006;
use strict;
use warnings;
use vars qw($VERSION);

# ----------------------------------------------------------
# 		       initialization
# ----------------------------------------------------------

my @FALLBACKS = qw(spf.mailzone.com);
my %SEVERITY = (pass => 00, softfail => 05, fail => 10, error => 20,
		defer_pass => 30, defer_softfail => 35, defer_fail => 40, unknown => 50);
($VERSION) = '$Id: Query.pm,v 1.2 2003/06/26 03:00:21 devel Exp $' =~ /([\d.]{3,})/;

# ----------------------------------------------------------
# 	 no user-serviceable parts below this line
# ----------------------------------------------------------

use Net::DNS;

my $looks_like_ipv4  = qr/\d+\.\d+\.\d+\.\d+/;
my $looks_like_email = qr/\S+\@\S+/;

=head1 NAME

Mail::SPF::Query - query Sender Permitted From for an IP,email

=head1 SYNOPSIS

  my $query = new Mail::SPF::Query (ip => "127.0.0.1", sender=>'foo@example.com');
  my ($result, $comment) = $query->result();

  if    ($result eq "pass") { ... } # mail is not spam
  elsif ($result eq "deny") { ... } # mail may be spam
  else                      { ... } # sender domain has not implemented SPF

=head1 ABSTRACT

The SPF protocol relies on sender domains to publish a DNS
whitelist of their designated outbound mailers.  Given an
envelope sender, Mail::SPF::Query determines the legitimacy
of an SMTP client IP.

=head2 Mail::SPF::Query->new()

  my $query = eval { new Mail::SPF::Query (ip => "127.0.0.1", sender=>'foo@example.com') };

                    optional parameters:   fallbacks => ["spf.mailzone.com", ...],
                                           debug => 1,

  if ($@) { warn "bad input to Mail::SPF::Query: $@" }

=cut

# ----------------------------------------------------------
sub new {
# ----------------------------------------------------------
  my $class = shift;
  my $query = bless { fallbacks=>\@FALLBACKS, @_ }, $class;

  $query->{ipv4} = delete $query->{ip} if $query->{ip} and $query->{ip} =~ $looks_like_ipv4;
  $query->debuglog("new: ipv4=$query->{ipv4}, sender=$query->{sender}");

  if (not ($query->{ipv4}   and length $query->{ipv4}))   { die "no IP address given to spfquery"   }
  if (not ($query->{sender} and length $query->{sender})) { die "no sender email given to spfquery" }

  ($query->{domain}) = $query->{sender} =~ /([^@]+)$/; # given foo@bar@baz.com, the domain is baz.com, not bar@baz.com.
  if (not length $query->{domain}) { die "unable to identify domain of sender $query->{sender}" }

  $query->{Reversed_IP} = ($query->{ipv4} ? reverse_in_addr($query->{ipv4}) :
			   $query->{ipv6} ? die "IPv6 not supported" : "");

  $query->post_new(@_) if $class->can("post_new");

  return $query;
}

=head2 $query->result()

  my ($result, $comment) = $query->result();

C<$result> will be one of C<pass>, C<fail>, C<softfail>, C<unknown>, or C<error>.

C<pass> means the client IP is a designated mailer for the sender's domain.

C<error> means the client IP is not.

C<unknown> means the domain does not publish SPF data.

C<error> means the DNS lookup encountered an error during processing.

=cut

# ----------------------------------------------------------
#			    spfmain
# ----------------------------------------------------------

sub result {
  my $query = shift;
  my %result_set;

  my $search_stack = [$query];

  my ($result, $text) = $query->spfquery($search_stack);

  $result =~ s/^defer_//i; # finalize deferrals.

  return $result, $text if wantarray;
  return $result        if not wantarray;
}


=head2 $query->debuglog()

  Subclasses may override this with their own debug logger.  I recommend Log::Dispatch.

=cut

sub debuglog {
  my $self = shift;
  return if ref $self and not $self->{debug};
  print STDERR join (" ", @_), "\n";
}

# ----------------------------------------------------------
#			    spfquery
# ----------------------------------------------------------

sub by_severity ($$) { $SEVERITY{$_[0]->[0]} <=> $SEVERITY{$_[1]->[0]} }

sub spfquery {
  my $self = shift;
  my $search_stack = shift;

  $self->debuglog("spfquery: --- @{[map { $_->{domain} } @$search_stack]}");

  my $query = pop @$search_stack;

  my ($lookup_result, $lookup_text) = $self->lookup($query, $search_stack);

  $self->{Domains_Queried}->{lc $query->{domain}} = [$lookup_result, $lookup_text];

  if ($lookup_result eq "pass" or
      $lookup_result eq "softfail" or
      $lookup_result eq "fail")                    { return $lookup_result, $lookup_text }
  if (not @$search_stack)                          { return $lookup_result, $lookup_text }

  # maybe "lookup" pushed some fallback or include domains onto the search stack.

  my ($spfquery_result, $spfquery_text) = $self->spfquery($search_stack);
  
  my @sorted_by_severity = sort by_severity my @to_sort = ([$lookup_result, $lookup_text], [$spfquery_result, $spfquery_text]);
  my ($result, $text) = @{$sorted_by_severity[0]};

  $self->{Domains_Queried}->{lc $query->{domain}} = [$result, $text];

  return $result, $text;
}

# ----------------------------------------------------------
#			    lookup
# ----------------------------------------------------------

sub lookup {
  my $self = shift;
  my %query = %{shift()};  my $domain = $query{domain};
  my $search_stack = shift;

  if ($self->{ipv4} =~ /^127\./) { return "pass", "localhost is always allowed." }
  
  if ($self->{Domains_Queried}->{lc $domain}) { $self->debuglog("  lookup: we have already processed $domain before.  returning its result.");
						return @{ $self->{Domains_Queried}->{lc $domain} }; }

  my $querystring = "$self->{Reversed_IP}._smtp_client.$domain";
  my $resquery = $self->resolver->query($querystring, "TXT");

  $self->debuglog("  lookup:  >> $querystring");

  my @toreturn;

  if (! $resquery) {
    # 
    # this could be an RFC1034 strict-conformance issue:
    # enclosed domains occlude wildcards.  look up _default._smtp_client instead.
    # 
    $self->debuglog("  lookup:   X query failed: ", $self->resolver->errorstring);

    my $defaultstring = "_default._smtp_client.$domain";
    $resquery = $self->resolver->query($defaultstring, "TXT");

    $self->debuglog("  lookup:  >> $defaultstring");
  }

  if ($resquery) {
    foreach my $rr ($resquery->answer) { $self->debuglog("  lookup:   < " . $rr->string); }

    # we will automatically get back a CNAME if the domain has no SPF TXT records.
    if (my ($cname) = grep { $_->type eq "CNAME" } $resquery->answer) {
      $self->debuglog("  lookup:  C  will use " . $cname->cname . " instead of $domain");
      push @$search_stack, { %query, domain => $cname->cname, fallback=>undef };
      return "unknown", "canonicalized to " . $cname->cname;
    }

    for my $txt (grep { $_->type eq "TXT" } $resquery->answer) {
      if (my $passfail = parsetxt($txt->rdatastr)) {
	if ($passfail eq "pass") {
	  $self->debuglog("  lookup:  T+ returning pass.");
	  return @toreturn = ("pass",
			      ("client " . $self->hostnamed_string($query{ipv4}) . " is designated mailer for domain of sender $query{sender}" .
			       ($query{fallback} ? " according to $query{fallback}" : "")),
			      );
	}
	
	if ($passfail eq "softfail" and $query{includehardenfail}) {
	  $self->debuglog("  lookup:  T- found $passfail; hardening to fail because we're looking up an included domain.");
	  $passfail = "fail";
	}

	if ($passfail eq "softfail") {
	  $self->debuglog("  lookup:  T- found $passfail.");
	  @toreturn = ($passfail,
		       ("client " . $self->hostnamed_string($query{ipv4}) . " is not a designated mailer for transitioning domain of sender $query{sender}" .
			($query{fallback} ? " according to $query{fallback}" : "")),
		       );
	}
	
	if ($passfail eq "fail") {
	  $self->debuglog("  lookup:  T- found $passfail.");
	  @toreturn = ($passfail,
		       ("client " . $self->hostnamed_string($query{ipv4}) . " is not a designated mailer for domain of sender $query{sender}" .
			($query{fallback} ? " according to $query{fallback}" : "")),
		       );
	}

	if ($passfail eq "unknown") {
	  $self->debuglog("  lookup:  T? found $passfail.");
	  return @toreturn = ($passfail,
			      ("domain of sender $query{sender} explicitly declines to participate in SPF" .
			       ($query{fallback} ? " according to $query{fallback}" : "")),
			      );
	}
      }
    }

    my @includes = map { $_->rdatastr =~ /^"?spfinclude=(\S+?)"?$/i } $resquery->answer;
    @includes = reverse sort sort_includes @includes;

    if (@includes) { $toreturn[0] = "defer_" . $toreturn[0] if @toreturn; }

    $self->debuglog("  lookup:  TI pushing on search stack: @includes") if @includes;
    push @$search_stack, map { { %query, (domain => /(.+?):/ ? $1 : $_), fallback=>undef, includehardenfail=>1 } } @includes;

    return @toreturn if @toreturn;
    
    return "unknown", "no data received for $query{domain}";
  }

  $self->debuglog("  lookup:   X query failed: ", $self->resolver->errorstring);

  #
  # now, fall-back if we didn't get any data.
  # 

  if (not $query{fallback} and $self->fallbacks) {
    # $self->debuglog("spfquery: falling back using", $self->fallbacks);
    push @$search_stack, map { { %query, domain => "$query{domain}.$_", fallback => $_ } } $self->fallbacks;
  }
#  else { $self->debuglog("spfquery: this is already a fallback domain, not falling back."); }

  return ("unknown", "domain of sender $query{sender} does not designate mailers: " . $self->resolver->errorstring .
	  ($query{fallback} ? " according to $query{fallback}" : ""));

}

# ----------------------------------------------------------
# 			 functions
# ----------------------------------------------------------

sub parsetxt {
  my $txt = shift;
  $txt =~ s/^"(.*)"$/$1/;
  my ($key, $value) = $txt =~ /^(spf\d*|dmp)\s*=(\S+)/i or return;
  return "pass" if ($value =~ /\b(allow|pass|ok|permit)\b/i);
  return "softfail" if ($value =~ /\b(softfail|softdeny)\b/i);
  return "fail" if $value =~ /\b(fail|deny)\b/i;
}

sub hostnamed_string {
  my $self = shift;
  my $ip = shift;
  my $query = $ip =~ $looks_like_ipv4 ? $self->resolver->query(reverse_in_addr($ip).".arpa", "PTR") : return; # ipv6 goes here
  if (not $query) {
    $self->debuglog("hostnamed_string: unable to PTR $ip");
    return "unknown[$ip]";
  }
  my ($hostname) = map { $_->type eq "PTR" ? $_->ptrdname : () } $query->answer;
  return (($hostname || "unknown") . "[$ip]");
}

sub reverse_in_addr {
  return join (".", (reverse split /\./, shift), "in-addr");
}

sub sort_includes ($$) {
  my ($a_name, $a_priority) = split /\|/, shift;    $a_priority ||= 0;
  my ($b_name, $b_priority) = split /\|/, shift;    $b_priority ||= 0;

  return $a_priority <=> $b_priority;
}

sub resolver {
  my $query = shift;
  return $query->{res} ||= Net::DNS::Resolver->new;
}

sub fallbacks {
  my $query = shift;
  return @{$query->{fallbacks}};
}

# ----------------------------------------------------------
# 		      algo
# ----------------------------------------------------------

=head1 Algorithm

input: SEARCH_STACK   = ([domain_name, is_fallback], ...)

returns: one of PASS | SOFTFAIL | FAIL | DEFER_PASS | DEFER_SOFTFAIL | DEFER_FAIL | UNKNOWN | ERROR , TEXT

data: LOOKUP_RESULT   = PASS | FAIL | DEFER_PASS | DEFER_FAIL | UNKNOWN | ERROR , TEXT
      SPFQUERY_RESULT = PASS | FAIL | DEFER_PASS | DEFER_FAIL | UNKNOWN | ERROR , TEXT

pop a DOMAIN off the top of the stack and run

  LOOKUP_RESULT, LOOKUP_TEXT = LOOKUP(DOMAIN, SEARCH_STACK).

as a side effect, LOOKUP may push new domains onto the top
of the SEARCH_STACK on the basis of SPFinclude replies.

They will be pushed with the attribute includehardenfail=1,
because SOFTDENY makes everything more complicated.  It
should be relevant for the top-level search but not in any
included domains.

If LOOKUP returns a PASS, a FAIL, or a SOFT_FAIL,
short-circuit the query by returning LOOKUP_RESULT,
LOOKUP_TEXT immediately.  That result will propagate all the
way back up the recursion stack.

If LOOKUP found any includes, it will return DEFER_FAIL or
DEFER_SOFTFAIL instead of FAIL or SOFTFAIL.  So try the
includes also before returning the current value.

If the search stack is empty, return the LOOKUP_RESULT, LOOKUP_TEXT.

To exhaust the search stack, we will recurse:

  SPFQUERY_RESULT, SPFQUERY_TEXT = SPFQUERY(SEARCH_STACK)

return the severer of LOOKUP_RESULT vs SPFQUERY_RESULT,
together with the appropriate TEXT.  Severity is defined
according to the following table:

     PASS	 
     FAIL	 
     SOFTFAIL	 
     ERROR	 
     DEFER_PASS
     DEFER_FAIL
     DEFER_SOFTFAIL
     UNKNOWN    

SEARCH ALGORITHM: lookup

global IP
global DOMAINS_QUERIED

lookup(DOMAIN, SEARCH_STACK):

Pop a domain off the top of the stack.

Have we queried this domain already?  If so, return nothing.

Perform a TXT query.  If the result contains

  CNAME: push the CNAME's target onto the SEARCH_STACK and return nothing.
  TXT SPF=allow: return PASS.
  TXT SPFinclude=domain.com: push all matching domain.com onto the SEARCH_STACK in reverse order of their [:priority].
  TXT SPF=fail: return FAIL if there were no includes; if there were includes, return DEFER_FAIL.
  TXT SPF=softfail: return SOFTFAIL if there were no includes; if there were includes, return DEFER_SOFTFAIL.

If the query failed or returned unknown, if the domain IS NOT FALLBACK,

  push the fallback versions of the current domain onto the
  top of the search stack:

    SEARCH_STACK = SEARCH_STACK map { "domain_name.$_" } FALLBACK_LIST

Then return unknown.

=head2 EXPORT

None by default.

=head1 AUTHOR

Meng Weng Wong, <mengwong+spf@pobox.com>

=head1 SEE ALSO

http://spf.pobox.com/

=cut

1;
