	

    #!/usr/bin/perl -wT
    # DNS Lookup v2
    # This was made as a learning practice in 2012
    use strict;
    use DBI;
    use JSON;
    use Net::DNS;
    use Net::DNS::RR;
    use Crypt::PasswdMD5;
    use base qw(CGI::Ex::App);
    use CGI::Ex::Dump qw(debug);
     
    my $dbh = DBI->connect('DBI:mysql:[database];host=localhost','charmst2_cgi','%Ey*1?cU;iDg',{AutoCommit => 0})
                || die "Could not connect to database: $DBI::errstr";
    my $dbresults = $dbh->selectall_hashref('SELECT * FROM henglong_users', 'Username');
    $dbh->disconnect();
     
    __PACKAGE__->navigate;
    exit;
     
    sub template_path { './templates' }
     
    sub login_hash_validation {
      return {
        username => {
          required => 1,
          match => 'm/^\w+$/',
          match_error => 'That is not one of the Usernames',
        },,
      };
    }
     
     
    sub login_finalize {
      my $self = shift;
      my $form = $self->form;
      my $username = $form->{'username'};
      my $password = $form->{'password'};
      my $salt = '&weis#2$sue%';
      my $md5pass = apache_md5_crypt($password, $salt);
      my $dbuser = $dbresults->{$username};
      my $person = $dbuser->{'FirstName'};
      my $user = $dbuser->{'Username'};
      if ($md5pass eq $dbuser->{'Password'}) {
        $self->cgix->set_cookie({
          name => 'lulogin',
          value => $person,
          expires => '+9h',
          path => '/',
        });
        $self->cgix->set_cookie({
          name => 'luuser',
          value => $user,
          expires => '+9h',
          path => '/',
        });
        $self->replace_path('main');
      } else {
        $self->add_to_form ({ loginfail => qq{<div class="domain"><center>Your username/password did not work</center></div>} ,});
        $self->append_path('login');
      }
      delete $form->{'username'};
      delete $form->{'password'};
      $self->set_ready_validate(0);
      return 1;
    }
     
    #sub main_hash_base {
    #  my $self = shift;
    #  debug $self->form;
    #}
     
    sub main_hash_fill {
      return {
        domain => '',
      };
    }
     
    sub main_hash_validation {
      return {
        domain => {
          required => 1,
          match => 'm/\w+\.\w+$/',
          match_error => 'It needs to be a domain name.',    
        },
      };
    }
     
    sub main_hash_swap {
      my $self = shift;
      my $person = $self->cookies->{'lulogin'};
      return {
        person => $person,
        cookie => $self->cookies,
      };
    }
     
    sub main_finalize {
      my $self = shift;
      my $domain = shift;
      my $form = $self->{'form'};
      $self->slap_domain($form->{'domain'});
      $self->append_path('main');
      delete $form->{'domain'};
      $self->set_ready_validate(0);
      return 1;
    }
     
    sub ajax_run_step {
      my $self = shift;
      my $form = $self->{'form'};
      $self->cgix->print_content_type("application/json");
      print to_json({$self->slap_domain($form->{'domain'})});
      $self->{'_no_post_navigate'} = 1;
      return 1;
    }
     
    sub slap_domain {
      my $self = shift;
      my $domain = shift;
      my $form;
      my $results = [];
      my $name = $form->{'domain'};
      my ($rr,@server,@jhserver,@bhserver,@ip,@jhip,@bhip,@nservers,@jhnservers,@bhnservers);
      my $dns = Net::DNS::Resolver->new;
      my $search = $dns->search($name);
      my $query = $dns->query($name, "NS");
      my @mx = mx($dns, $name);
      if ($search) {
        foreach $rr ($search->answer) {
          next unless $rr->type eq "A";
          push (@ip, $rr->address);
        }
        foreach $rr (grep { $_->type eq 'NS'} $query->answer) {
          push (@nservers, $rr->nsdname);
        }
        foreach $rr (@mx) {
        }
        foreach my $ptr_search ($dns->query(@ip, 'PTR')) {
          foreach $rr ($ptr_search->answer) {
            next unless $rr->type eq 'PTR';
            push (@server, $rr->ptrdname);
          }
        }
      }
      $results = {
        ip => \@ip,
        nserver => \@nservers,
        server => \@server
      };
      return to_json ($results);
    }
     
    sub account_hash_swap {
      my $self = shift;
      my $person = $self->cookies->{'lulogin'};
      my $username = $self->cookies->{'luuser'};
      my $info = $dbresults->{$username};
      my $fname = $info->{'FirstName'};
      my $lname = $info->{'LastName'};
      return {
        fname => $info->{'FirstName'},
        lname => $info->{'LastName'},
        username => $username,
        email => $info->{'Email'},
        info => \$info,
        person => $person,
      };
    }
     
    sub account_finalize {
      my $dbh = DBI->connect('DBI:mysql:[database];host=localhost','charmst2_cgi','%Ey*1?cU;iDg',{AutoCommit => 0})
                || die "Could not connect to database: $DBI::errstr";
      my $self = shift;
      my $username = $self->cookies->{'luuser'};
      my $form = $self->form;
      my $newfname = $form->{'fname'};
      my $newlname = $form->{'lname'};
      my $newemail = $form->{'email'};
      if ($newfname) {
        $dbh->do("UPDATE henglong_users SET FirstName='$newfname' WHERE Username='$username'");
      }
      if ($newlname) {
        $dbh->do("UPDATE henglong_users SET LastName='$newlname' WHERE Username='$username'");
      }
      if ($newemail) {
        $dbh->do("UPDATE henglong_users SET Email='$newemail' WHERE Username='$username'");
      }
      $dbh->disconnect();
      $self->append_path('account');
    #  delete $form->{'fname'};
    #  delete $form->{'lname'};
    #  delete $form->{'email'};
      $self->set_ready_validate(0);
      return 1;
    }
     
    __END__

