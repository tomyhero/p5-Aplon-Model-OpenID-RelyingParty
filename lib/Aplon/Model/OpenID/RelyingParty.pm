package Aplon::Model::OpenID::RelyingParty;
use strict;
use Mouse;
extends 'Aplon';
with 'Aplon::Validator::Simple';

our $VERSION = '0.01';

use OpenID::Lite::RelyingParty;
use OpenID::Lite::RelyingParty::Store::OnMemory;
use OpenID::Lite::Constants::AssocType ;
use OpenID::Lite::Constants::SessionType ;
use Mouse::Util;

has 'openid' => (
    is => 'rw',
    lazy_build => 1,
);

has 'session' => (
    is => 'rw',
    required => 1,
);

has error_class => (
    is => 'rw',
    default => 'Aplon::Error',
);

has realm => (
    is => 'rw',
    required => 1,
);
has return_to => (
    is => 'rw',
    required => 1,
);


sub BUILD {
    my $self = shift;
    Mouse::Util::load_class($self->error_class);
}

sub store_obj {
    my $self = shift;
    if( my $store = $self->session->get($self->openid_store_key) ){
        return $store;
    }
    else {
        my $store = OpenID::Lite::RelyingParty::Store::OnMemory->new;
        $self->session->set($self->openid_store_key, $store);
        return $store;
    }
}

sub _build_openid {
    my $self = shift;

    return OpenID::Lite::RelyingParty->new( 
        assoc_type => OpenID::Lite::Constants::AssocType::HMAC_SHA1,
        session_type => OpenID::Lite::Constants::SessionType::DH_SHA1,
        session => $self->session,
        store => $self->store_obj,
    );
}

sub login {
    my $self = shift;
    my $args = shift;
    my $user_suplied_identifier = $args->{openid_identifier}  or $self->abort_with({ 
        code => "OPENID_FAILED" ,
        missing => ['openid_identifier'],
    }); 

    my $openid = $self->openid;
    my $checkid_request = $openid->begin( $user_suplied_identifier );
    
    unless($checkid_request){
        $self->abort_with({ 
            code => "OPENID_FAILED" ,
            custom_invalid => [ 'openid_begin_faild' ],
        });
    }

    my $redirect_url = $checkid_request->redirect_url(
            return_to => $self->return_to,
            realm     => $self->realm,
            );

    return $redirect_url;
}

sub complete {
    my $self = shift;
    my $args = shift;
    my $openid = $self->openid;
    my $res = $openid->complete( $args , $self->return_to );
    $self->session->remove($self->openid_store_key);
    if ( $res->is_success ) {
        $self->do_complate($res);
    }
    else {
        #warn $res->type;
        #warn $res->message;
        $self->abort_with({ 
            code => "OPENID_FAILED",
            custom_invalid => [ 'complate_failed' ],
            message => $res->message,

        });
    }
    return 1;
}

sub do_complate {
    my $self = shift;
    my $res = shift ; # OpenID::Lite::RelyingParty::CheckID::Result;
    die 'do_complate() is ABSTRACT method';
}

sub openid_store_key {
    my $self = shift;
    my $key = ref $self . '::__openid_store';
}

__PACKAGE__->meta->make_immutable();

no Mouse;

1;

=head1 NAME

Aplon::Model::OpenID::RelyingParty - OpenID RelyingParty Model with OpenID::Lite module.

=head1 SYNOPSIS


 package Zerg::Model::OpenID;
 use strict;
 use Mouse;
 use Zerg::Aplon::Error;
 extends 'Aplon::Model::OpenID::RelyingParty';
 
 has '+realm' => (
     default => 'http://zerg.example.com/',
 );
 has '+return_to' => (
     default => 'http://zerg.example.com/auth/openid/complete/',
 );
 
 has '+error_class' => (
     default => 'Zerg::Aplon::Error',
 );
 
sub do_complate {
    my $self = shift;
    my $res = shift ;  # OpenID::Lite::RelyingParty::CheckID::Result


    # do something with $res 


    1;
}

 __PACKAGE__->meta->make_immutable();
 
 no Mouse;
 
 1;
 

 # login
 {
    my $model = Zerg::Model::OpenID->new({session => $session}) ; # $session should support get() set() remove()
    $c->redirect( $model->login( { openid_identifier => 'hoge' } ) );
 }

 # complete
 {
    my $model = Zerg::Model::OpenID->new({session => $session}) ;
    $model->complete( $req_params );
 }

=head1 DESCRIPTION

this model help you to create OpenID login logic easier.

=head1 AUTHOR

Tomohiro Teranishi 

=head1 SEE ALSO

L<Aplon>

L<OpenID::Lite>

=cut
