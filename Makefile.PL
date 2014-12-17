use 5.008002;
use ExtUtils::MakeMaker;

download_crypt_blowfish();

WriteMakefile(
    NAME              => 'Crypt::Blowfish::XS',
    VERSION_FROM      => 'XS.pm',
    PREREQ_PM         => {"Crypt::Random" => 0},
    OBJECT => 'XS.o crypt_blowfish.o'
);

sub MY::test_via_harness {
        "\tprove -b -r t"
}

sub download_crypt_blowfish {
  `curl http://www.openwall.com/crypt/crypt_blowfish-1.3.tar.gz | tar zx --strip-components=1 */crypt_blowfish.[ch]`;
}

