use strict;
use warnings;
use lib "/var/www/html/bugzilla/lib";  # use (bugzilla local lib. To be changed if the directory is not the same)
use Net::LDAPS;
use Date::Calc qw(Delta_Days);
use MIME::Lite;
use POSIX;

#ldap params
my $ldap_host = "ldaps://172.31.1.67";
my $ldap_port = "636";
my $seconds_in_a_day = 86400;
my $ldap_users_dn = "ou=Users,dc=stforge,dc=com";
my $ldap_users_filter = "(&(memberOf=cn=BugzillaProd,ou=Profiles,dc=stforge,dc=com)(pwdChangedTime=*))";
my $ldap_policy_dn = "ou=Policies,dc=stforge,dc=com";
my $ldap_policy_filter = "(cn=DefaultPassword)";
my $ldap_login = "uid=notifications_ldap,ou=Administration,dc=stforge,dc=com";
my $ldap_passwd = "PJiig2ph";

#server mail address
my $server_mail = 'stforge.admin@st.com';

my $error_mail_body = "";

#days shift in which the users would be notified
my @days_threshold = (30, 14, 7, 3, 2, 1);

my $log_file = "$0.log";
my $path_to_attachment = "ressources/STforge_Bugzilla_Passwd_Policy_Guide.pdf";

my $admin_mail='mohamedamin.doghri@st.com';

#current date concatenated
my $current_date = strftime "%Y%m%d", localtime;

sub ldap_response {
        my($ldap, $ldap_login, $ldap_passwd, $ldap_users_dn, $filter) = @_;
        $ldap->bind($ldap_login, password => $ldap_passwd, version => 3);
        my $mesg = $ldap->search(filter=>$filter,
                                attrs=>['*','+'],
                                base=> $ldap_users_dn);
        my @entries = $mesg->entries;
        if ( $mesg->code ) {
                $error_mail_body .= "LDAP bind problem : " . $mesg->error ."<br>";
                logit($log_file, "LDAP bind problem : " . $mesg->error);
        }
        return @entries;
}

#-- logging to a given file
sub logit {
        my($log_file, $msg) = @_;
        my $date = strftime "%m/%d/%Y", localtime;
        open(my $fh, '>>', $log_file)or die "can't open file '$log_file' $!";;
        print $fh "[$date] $msg\n";
        close $fh;
}

#-- send mail with the given infos
sub send_mail {
        my($to, $cc, $from, $subject, $message, $path_to_attachment) = @_;
        my $msg = MIME::Lite->new(
                 From     => $from,
                 To       => $to,
                 Cc       => $cc,
                 Subject  => $subject,
                 Data     => $message,
                 Type    =>'text/html'
                 );
        if ($path_to_attachment ne "none") {
                $msg->attach(  Type        =>  'application/pdf',
                        Path        =>  $path_to_attachment,
                        Filename    =>  'email_renewal_procedure.pdf',
                        Disposition =>  'attachment'
                );
                $msg->attr("content-type"  => "multipart/mixed");
        }
        $msg->send;
}

# --Main
my @entries_users;
my @entry_policy;

my $ldap = Net::LDAPS->new($ldap_host,
                          port => $ldap_port,
                          verify => 'none'
                          );
if ($ldap) {
        @entries_users = ldap_response($ldap, $ldap_login, $ldap_passwd, $ldap_users_dn, $ldap_users_filter);
        @entry_policy = ldap_response($ldap, $ldap_login, $ldap_passwd, $ldap_policy_dn, $ldap_policy_filter);
} else {
        $error_mail_body .= "LDAP instantiation problem : " . $@ ."<br>";
        logit($log_file, "LDAP instantiation problem : " . $@);
}

my $users_number_passwd_change_warning = 0;
my $pwd_max_age = $entry_policy[0]->get_value("pwdMaxAge") / $seconds_in_a_day;
my $attempts_left = $entry_policy[0]->get_value("pwdGraceAuthNLimit");
foreach my $entry (@entries_users) {
        #set to bypass warnings
        no warnings 'uninitialized';
        if(! ($entry->get_value("pwdPolicySubentry") =~ "NoExpirePassword")){
                my $pwd_changed_time = substr($entry->get_value("pwdChangedTime"),0,8);
                my $pw_days_left = Delta_Days(substr($current_date,0,4), substr($current_date,4,2), substr($current_date,6,2),substr($pwd_changed_time,0,4), substr($pwd_changed_time,4,2), substr($pwd_changed_time,6,2));
                $pw_days_left += $pwd_max_age;
                foreach my $days_left (@days_threshold) {
                        if($pw_days_left eq $days_left) {
                                my $user = $entry->get_value("cn");
                                my $mail_body = "<font face=verdana size=2 color=#2A4FB5>Dear Customer,<br><br>
Your password will expire in <b>$pw_days_left days</b>,please find attached the guidelines (attached file) to change your password.<br><br>
You must be logged on ST Bugzilla 2 to change your password. If you can't log on, please request password through ST forge portal (button forgot password)<br><br>
You have : $pw_days_left day(s) to change your password<br>
- <b>$attempts_left attempts</b> are still allowed<br><br>
In case of issue please send us (<mailto>ictservicedesk\@st.com</mailto>) a ticket (as change password request)<br><br>
-- The STforge Team --</font>";

                                send_mail($entry->get_value("mail"), "", $server_mail, "password expiry notification", $mail_body, $path_to_attachment);
                                logit($log_file, "$user : $pw_days_left");
                        }
                }
        }
}
if ($error_mail_body ne "") {
         send_mail($admin_mail, "", $server_mail, "password expiry notification errors", $error_mail_body, "none");
}

if ($ldap) {
        $ldap->unbind;
}
exit 0;
