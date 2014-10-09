use 5.008002;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Crypt::Blowfish::XS',
    VERSION_FROM      => 'XS.pm',
    PREREQ_PM         => {},
    OBJECT => 'XS.o crypt_blowfish.o'
);

sub MY::test_via_harness {
        "\tprove -b -r t"
}

