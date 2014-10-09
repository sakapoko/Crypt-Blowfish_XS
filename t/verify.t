use strict;
use warnings;
use Crypt::Blowfish::XS;
use Test::More;

my $key = 'bg2Loua\`h2#';
my $hash = Crypt::Blowfish::XS::salted_bcrypt($key, 10);

ok(length($hash) == 60);

ok(Crypt::Blowfish::XS::bcrypt($key, $hash) eq $hash);

done_testing();

