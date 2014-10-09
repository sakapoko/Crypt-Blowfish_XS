package Crypt::Blowfish::XS;
use strict;
use warnings;
use Crypt::Random qw/makerandom/;
use Exporter;
use XSLoader;

our @ISA = qw/Exporter/;
our @EXPORT_OK = qw/bcrypt bcrypt_gensalt salted_bcrypt/;
our $VERSION = '0.01';

XSLoader::load __PACKAGE__, $VERSION;

sub bcrypt {
  my ($key, $settings) = @_;
  _crypt_blowfish($key, $settings);
}

sub bcrypt_gensalt {
  my ($prefix, $count, $input, $size) = @_;
  _crypt_gensalt($prefix, $count, $input, $size);
}

sub salted_bcrypt {
  my ($key, $cost) = @_;
  &bcrypt(
    $key,
    &bcrypt_gensalt(
      '$2y$',
      $cost,
      pack("q2", makerandom(Size => 64, Strength => 0), makerandom(Size => 64, Strength => 0)),
      16
    )
  );
}

1;

=pod

=encoding utf-8

=head1 NAME

Crypt::Blowfish::XS - Perl binding of crypt_blowfish.

=head1 SYNOPSIS

 use Crypt::Blowfish::XS qw/bcrypt bcrypt_gensalt salted_bcrypt/;
 use Crypt::Random qw/makerandom/;

 $word = pack("q2",
   makerandom(Size => 64, Strength => 0),
   makerandom(Size => 64, Strength => 0)
 );
 $salt = bcrypt_gensalt('$2y$', 10, $word, 16);
 $hash = bcrypt('key', $salt);

or

 $hash = salted_bcrypt('key', 10); # with random salt

=head1 DESCRIPTION

This module is Perl binding of crypt_blowfish.
Crypt code is delivered by openwall L<http://www.openwall.com/crypt/>.

=head1 METHODS

=over

=item bcrypt(key, settings)

Return bcrypted hash string.


=item bcrypt_gensalt

=item salted_bcrypt

=head1 SEE ALSO

openwall L<http://www.openwall.com/crypt/>

=head1 AUTHOR

Shuji Sakagami <sakapoko@gmail.com>

=cut
