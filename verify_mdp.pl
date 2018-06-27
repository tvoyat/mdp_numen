#!/usr/bin/perl -w
# -*- coding: utf-8 -*-
# Vérification de Numen=mdp pour les uids depuis un fichier export.ldif
#
# Thierry.voyat@ac-amiens.fr


use strict;
use warnings;
use Getopt::Long;
use Data::Dumper;
use POSIX qw/strftime/;
use Digest::SHA; # apt-get install libdigest-sha-perl
use MIME::Base64;


# Traitement des options de la ligne de commande et valeurs par défaut
my %optctl = ();
$optctl{'domaine'} = "ac-amiens.fr";
$optctl{'ldif'}    = "export.ldif";

GetOptions("help"                 => \$optctl{'help'},
           "d|debug:+"            => \$optctl{'debug'},
           "version"              => \$optctl{'version'},
           "ldif:s"               => \$optctl{'ldif'},
           "skip:n"               => \$optctl{'skip'},
       );


my %hashlen = (
    'smd5'    => 16,
    'ssha'    => 20,
    'ssha256' => 32,
    'ssha512' => 64,
);


# Date du jour
my $dermaj = strftime('%d/%m/%Y',localtime);
my %d; # Tampon data fiche en cours



sub split_scheme() {
    my $pass =shift;
    my ($scheme, $pw);
    my $algo = "plain";
    # Identifie le schema du mot de passe
    if ( ($pw = $pass) =~ s/^\{([^}]+)\}// ) {
        $algo = lc($1);        
    }
    return ($algo, $pw);
}

sub split_salt() {
    my $pwscheme = shift;
    my $pw = shift;

    # voir http://blog.gauner.org/2010/12/handling-salted-passwords-in-perl/
    
    my $hashlen = $hashlen{$pwscheme};
    # pwscheme could also specify an encoding
    # like hex or base64, but right now we assume its b64
    $pw = MIME::Base64::decode($pw);

    # unpack byte-by-byte, the hash uses the full eight bit of each byte,
    # the salt may do so, too.
    my @tmp  = unpack( 'C*', $pw );
    my $i    = 0;
    my @hash = ();

    # the salted hash has the form: $saltedhash.$salt,
    # so the first bytes (# $hashlen) are the hash, the rest
    # is the variable length salt
    while ( $i < $hashlen ) {
        push( @hash, shift(@tmp) );
        $i++;
    }

    # as I've said: the rest is the salt
    my @salt = ();
    foreach my $ele (@tmp) {
        push( @salt, $ele );
        $i++;
    }

    # pack it again, byte-by-byte
    my $salt = pack( 'C*', @salt );
    
    return $salt;
}

sub ssha() {
    my $pw = shift;
    my $salt = shift;
    return "{SSHA}" . MIME::Base64::encode( Digest::SHA::sha1( $pw . $salt ) . $salt, '' );
}

sub sha() {
    my $pw = shift;
    return "{SHA}" . MIME::Base64::encode( Digest::SHA::sha1($pw), '' );
}

sub mk_passwd() {
    my $salt;
    my $scheme;
    my $pw;
    
    ($scheme, $pw) = &split_scheme( $d{userpassword} );
    
    if ( $scheme eq 'crypt' ) {
        $salt = substr($pw, 0, 2);
        return "{crypt}".crypt ($d{employeenumber}, $salt);
    }
    if ( $scheme eq 'ssha' ) {
        $salt = &split_salt( $scheme, $pw);
        return &ssha($d{employeenumber}, $salt);
    }
    elsif ( $scheme eq 'sha' ) {
        return &sha($d{employeenumber});
    }
    else {
        print "Algo inconnu : $salt\n";
    }
}

sub verif_mdp() {
    # Verification du couple Numen Mdp
    my $testpassword = &mk_passwd;
    if ( $d{userpassword} eq $testpassword ) {
        print join(";", $d{uid}, $d{mail}|| "<PAS_DE_MAIL>","\n");
    }
}

sub read_ldif() {
    # "recolle" les lignes splitées
    my $sed='sed -e :a -e \'$!N;s/\n //;ta\' -e \'P;D\' '; 
    my $LDIF = "$sed $optctl{ldif} |";
    open(FH, "$LDIF") or die "Impossible de lire l'extraction --ldif ", $optctl{ldif},"\n" ;

    while (<FH>) {
        if (/^dn: /o) { # Nouvelle entrée
            if ( defined $d{uid} and defined $d{employeenumber} and defined $d{userpassword} ) {
                verif_mdp;
            }
            %d=();
            next;
        }
        next if not /^(userPassword|employeeNumber|uid|mail)(;.*)?\: /o;
        next if  /;deleted: /o;
        
        if (/^(\w*)(?:;.*)?\: (.*)$/) {
            my $tmp1 = lc($1);
            my $tmp2 =$2;
            $d{$tmp1}=$tmp2; # Mémoire fiche en cours
        }
    }
}
    
binmode(STDIN,":utf8");
$| =1;

# Chargement des numens, uids et adresses mails de puis un export ldap
&read_ldif();

