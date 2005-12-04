#!/usr/bin/perl

package Catalyst::Plugin::Session::PerUser;
use base qw/Class::Accessor::Fast/;

use strict;
use warnings;

our $VERSION = "0.02";

use Hash::Merge ();

BEGIN {
    __PACKAGE__->mk_accessors(qw/_user_session/);
}

sub setup {
    my $self = shift;

    my $cfg = $self->config->{user_session} ||= {};

    %$cfg = (
        migrate => 1,
        merge_type => "RIGHT_PRECEDENT",
        %$cfg,
    );

    $self->NEXT::setup;
}

sub set_authenticated {
    my $c = shift;
    $c->NEXT::set_authenticated(@_);

    $c->log->debug("user logging in") if $c->debug;

    if ( $c->config->{user_session}{migrate} ) {
        $c->merge_session_to_user;
    }
}

sub logout {
    my $c = shift;
    
    $c->store_user_session_in_session_store;
    $c->_user_session(undef);
    
    $c->NEXT::logout(@_);
}

sub user_session {
    my $c = shift;

    if ( my $user = $c->user ) {
        $c->log->debug("user logged in, using user session") if $c->debug;
        if ( $c->user->supports("session_data") ) {
            return $user->session_data || $user->session_data( {} );
        }
        else {
            return $c->_user_session
              || $c->_user_session( $c->get_user_session_from_session_store )
              || $c->_user_session( {} );
        }
    }
    else {
        $c->log->debug("no user logged in, using guest session") if $c->debug;
        return $c->session;
    }
}

sub get_user_session_from_session_store {
    my $c = shift;
    $c->log->debug("loading data from user session") if $c->debug;
    $c->get_session_data( $c->user_session_sid );
}

sub store_user_session_in_session_store {
    my $c = shift;

    if ( my $data = $c->_user_session ) {
        $c->log->debug("storing data in user session") if $c->debug;
        $c->store_session_data( $c->user_session_sid, $data );
    }
}

sub finalize {
    my $c = shift;

    $c->store_user_session_in_session_store;

    $c->NEXT::finalize(@_);
}

sub user_session_sid {
    my $c = shift;
    "user:" . $c->user->id;
}

sub merge_session_to_user {
    my $c = shift;

    $c->log->debug("merging guest session into per user session") if $c->debug;

    my $merge_behavior = Hash::Merge::get_behavior;
    my $clone_behavior = Hash::Merge::get_clone_behavior;

    Hash::Merge::set_behavior( $c->config->{user_session}{merge_type} );
    Hash::Merge::set_clone_behavior(0);

    my $s    = $c->session;
    my @keys =
      grep { !/^__/ } keys %$s;    # __user, __expires, etc don't apply here

    my %right;
    @right{@keys} = delete @{$s}{@keys};

    %{ $c->user_session } =
      %{ Hash::Merge::merge( $c->user_session || {}, \%right ) };

    Hash::Merge::set_behavior($merge_behavior);
    Hash::Merge::set_clone_behavior($clone_behavior);
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Session::PerUser - Per user sessions (instead of per
browser sessions).

=head1 SYNOPSIS

	use Catalyst qw/
		Session
		Authentication
		Authentication::Store::Foo
		Session::PerUser
	/;

	sub action : Local {
		my ( $self, $c ) = @_;
		$c->user_session->{foo} = "bar";
	}

=head1 DESCRIPTION

This plugin allows you to write e.g. shopping cart code which should behave
well for guests as well as permanent users.

The basic idea is both logged in and not logged in users can get the same
benefits from sessions where it doesn't matter, but that logged in users can
keep their sessions accross logins, and will even get the data they
added/changed assimilated to their permanent account if they made the changes
as guests and then logged in.

This is probably most useful for e-commerce sites, where the shopping cart is
typically used before login, and should be equally accessible to both guests
and logged in users.

=head1 STORING SESSION DATA

This module can store session data in two ways:

=head2 Within the User

If C<<$c->user->supports("session_data")>> then C<<$c->user->session_data>> is
used as an accessor to store the per-user session hash reference.

This is useful for L<Catalyst::Plugin::Authentication::Store> implementations
that rely on a database or another fast, extensible format.

=head2 Within the Session Store

If the user does not support the C<session_data> feature, the
L<Catalyst::Plugin::Session::Store> plugin in use will be used to save the
session data instead.

The session ID used to save this data is set by C<user_session_sid>.

Note that this method could potentially have security issues if you override
the default C<user_session_sid> or
L<Catalyst::Plugin::Session/validate_session_id>. See L</CAVEATS> for details.

=head1 METHODS

=over 4

=item user_session

If no user is logged in, returns C<<$c->session>>.

If a user is logged in, and C<<$user->supports("session_data")>> it will return
C<<$c->user->session_data>>. Otherwise it will return
C<<$c->user_session_from_session_store>>.

=back

=head1 INTERNAL METHODS

=over 4

=item merge_session_to_user

Uses L<Hash::Merge> to merge the browser session into the user session,
omitting the special keys from the browser session.

Should be overloaded to e.g. merge shopping cart items more smartly.

=item get_user_session_from_session_store

Uses the C<Catalyst::Plugin::Session::Store> api to get a session data chunk
whose session ID is C<user_session_sid>.

=item store_user_session_in_session_store

Stores the session data cached by C<user_session_from_session_store>.

=item user_session_sid

Returns

	"user:" . $c->user->id

=back

=head1 EXTENDED METHODS

=over 4

=item set_authenticated

Calls C<merge_session_to_user>

=back

=head1 CONFIGURATION

	$c->config->{user_session} = {
        ...
    };

=over 4

=item migrate

Whether C<< $c->session >> should be merged over C<< $c->user_session >> on
login. On by default.

=item merge_type

Passed to L<Hash::Merge/set_behavior>. Defaults to C<RIGHT_PRECEDENT>.

=item 

=back

=item CAVEATS

If you override L<Catalyst::Plugin::Session/validate_session_id> make sure it's
format B<DOES NOT ALLOW> the format returned by C<user_session_sid>, or
malicious users could potentially set their cookies to have sessions formatted
like a string returned by C<user_session_sid>, and steal or destroy another
user's session without authenticating.
=back

=head1 SEE ALSO

L<Catalyst::Plugin::Authentication>, L<Catalyst::Plugin::Session>

=head1 AUTHORS

David Kamholz, C<dkamholz@cpan.org>

Yuval Kogman, C<nothingmuch@woobling.org>

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut

