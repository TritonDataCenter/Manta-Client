package Manta::Client;

use strict;
use warnings;
use Carp qw(croak);
use Crypt::OpenSSL::RSA;
use MIME::Base64 qw(encode_base64);
use Net::SSH::Perl::Key;
use LWP::UserAgent;
use Data::Dumper;

sub new {
	my $class = shift;
	croak "Illegal parameter list has odd number of values" if @_ % 2;
	my %params = @_;
	my $self = {};
	bless $self, $class;
	for my $required (qw{ user url key_file }) {
		croak "Required parameter '$required' not passed to '$class' constructor" unless defined $params{$required};  
		$self->{$required} = $params{$required};
	}
	return $self;
}

sub _request {
	my $self = shift;
	croak "Illegal parameter list has odd number of values" if @_ % 2;
	my %params = @_;
	for my $required (qw{ method path }) {
		croak "Required parameter '$required' not passed to _request method" unless defined $params{$required};  
	}
	my $date = scalar gmtime;
	my $date_header = "date: $date";
	open F, "<$self->{key_file}";
	my $key = join '', <F>;
	close F;
	my $fingerprint = Net::SSH::Perl::Key->read_private("RSA", $self->{key_file})->fingerprint("md5");
	my $privatekey = Crypt::OpenSSL::RSA->new_private_key($key);
	$privatekey->use_sha256_hash();
	my $signature = encode_base64($privatekey->sign($date_header), "");
	my $h = HTTP::Headers->new(%{$params{headers}});
	$h->header(date => $date);
	$h->header('Authorization' => "Signature keyId=\"/$self->{user}/keys/$fingerprint\",algorithm=\"rsa-sha256\",signature=\"$signature\"");
	my $ua = LWP::UserAgent->new;
	my $response;
	if ($params{method} eq "GET") {
		$response = $ua->get("$self->{url}/$params{path}");
		if ($response->is_success) {
			return $response->decoded_content;
		} else {
			return undef;
		}
	} elsif ($params{method} eq "PUT") {
		$response = $ua->put("$self->{url}/$params{path}", Content => $params{content}, %$h);
		return !!$response->is_success;
	} elsif ($params{method} eq "DELETE") {
		$response = $ua->delete("$self->{url}/$params{path}");
		return !!$response->is_success;
	} else {
		croak ("bad method");
	}
}

sub get {
	my ($self, $path) = @_;
	my $response = $self->_request(path => $path, method => "GET");
	return $response;
}

sub put {
	my $self = shift;
	croak "Illegal parameter list has odd number of values" if @_ % 2;
	my %params = @_;
	croak "Required parameter 'path' not passed to put method put" unless defined $params{path};
	return $self->_request(path => $params{path}, method => "PUT", content => $params{content}, headers => {"content-type" => $params{"content-type"}});
}

sub rm {
	my ($self, $path) = @_;
	my $response = $self->_request(path => $path, method => "DELETE");
	return $response;
}

sub mkdir {
	my ($self, $path) = @_;
	return $self->put(path => $path, "content-type" => "application/json; type=directory");
}

1;
