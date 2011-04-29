use inc::Module::Install;
name 'Aplon-Model-OpenID-RelyingParty';
all_from 'lib/Aplon/Model/OpenID/RelyingParty.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
