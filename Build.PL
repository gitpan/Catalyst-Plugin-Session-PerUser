use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Catalyst::Plugin::Session::PerUser',
    requires           => {
        'Catalyst::Plugin::Session'         => '0.01',
        'Catalyst::Plugin::Authentication'  => '0.01',
        'Hash::Merge'                       => 0,
        'Object::Signature'                 => 0,
    },
    create_readme => 1,
#    sign          => 1,
);
$build->create_build_script;

