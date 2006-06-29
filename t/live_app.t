#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 43;

{

    package User::WithSession;
    use base qw/Catalyst::Plugin::Authentication::User::Hash/;

    sub supports {
        my ( $self, $feature ) = @_;

        $feature eq "session_data" || $self->SUPER::supports($feature);
    }
    
    sub get_session_data {
        return shift->{session_data};
    }
    
    sub store_session_data {
        my ( $self, $data ) = @_;
        return $self->{session_data} = $data;
    }

    package PerUserTestApp;
    use Catalyst qw/
      Session
      Session::Store::Dummy
      Session::State::Cookie

      Session::PerUser

      Authentication
      Authentication::Store::Minimal
      /;

    sub add_item : Local {
        my ( $self, $c, $item ) = @_;

        $c->user_session->{items}{$item} = 1;
    }

    sub show_items : Local {
        my ( $self, $c, $item ) = @_;

        $c->res->body(
            join( ", ", sort keys %{ $c->user_session->{items} ||= {} } ) );
    }

    sub auth_login : Local {
        my ( $self, $c, $name ) = @_;
        $c->set_authenticated( $c->get_user($name) );
    }

    sub auth_logout : Local {
        my ( $self, $c ) = @_;

        $c->logout;
    }

    __PACKAGE__->config->{authentication}{users} = {
        foo   => { id                       => "foo" },
        bar   => { id                       => "bar" },
        gorch => User::WithSession->new( id => "gorch" ),
    };

    __PACKAGE__->setup;
}

use Test::WWW::Mechanize::Catalyst 'PerUserTestApp';

my $m = Test::WWW::Mechanize::Catalyst->new;
my $h = "http://localhost";

$m->get_ok("$h/show_items");
$m->content_is("");

$m->get_ok("$h/add_item/foo");

$m->get_ok("$h/show_items");
$m->content_is( "foo", "added item" );

$m->get_ok("$h/add_item/bar");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/foo bar/ ), "added both items" );

$m->get_ok("$h/auth_login/foo");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/foo bar/ ),
    "items still there after login" );

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/show_items");
$m->content_is( "", "items gone after logout" );

$m->get_ok("$h/auth_login/foo");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/foo bar/ ), "items restored after login" );

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/auth_login/bar");

$m->get_ok("$h/add_item/gorch");

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/auth_login/foo");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/foo bar/ ),
    "items restored with intermediate other user" );

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/add_item/ding");

$m->get_ok("$h/add_item/baz");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/ding baz/ ), "new items for a guest user" );

$m->get_ok("$h/auth_login/foo");

$m->get_ok("$h/show_items");
$m->content_is(
    join( ", ", sort qw/foo bar ding baz/ ),
"session data merged, items from user session and guest session are both there"
);

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/auth_login/gorch");

$m->get_ok("$h/add_item/moose");

$m->get_ok("$h/auth_logout");

$m->get_ok("$h/add_item/elk");

$m->get_ok("$h/show_items");
$m->content_is( "elk", "new items for a guest user" );

$m->get_ok("$h/auth_login/gorch");

$m->get_ok("$h/show_items");
$m->content_is( join( ", ", sort qw/elk moose/ ),
    "items merged with in-user store" );

is_deeply(
    [
        sort keys %{ PerUserTestApp->config->{authentication}{users}{gorch}
              ->get_session_data->{items}
          }
    ],
    [qw/elk moose/],
    "all items in user->session_data"
);
