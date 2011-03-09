package Catalyst::Plugin::Session::State::Auth;
use Moose;
use HTTP::Headers::Util qw(split_header_words);
use MRO::Compat;

use namespace::clean -except => 'meta';

our $VERSION = '0.001';

extends 'Catalyst::Plugin::Session::State';
with 'MooseX::Emulate::Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw/_sessionid_from_auth_signature/);

sub get_session_id {
    my ( $c, @args ) = @_;
    return $c->_sessionid_from_auth_signature || $c->maybe::next::method(@args);
}

sub finalize {
    my $c = shift;
    return $c->maybe::next::method(@_);
}

sub prepare_action {
    my $c = shift;
    my @values = split_header_words( $c->request->header('authorization') );
    $sid       = $values[-1][-1];
    $c->_sessionid_from_uri( $sid );
    $c->log->debug(qq/Found sessionid "$sid" in Authorization: signature/) if $c->debug;
    return $c->maybe::next::method(@_);
}

__PACKAGE__

__END__

1;

=head1 NAME

Catalyst::Plugin::Session::State::Auth - 

=head1 DESCRIPTION

=head1 METHODS

=head1 BUGS

=head1 AUTHOR

=head1 COPYRIGHT & LICENSE

Copyright 2009 the above author(s).

This sofware is free software, and is licensed under the same terms as perl itself.

=cut

