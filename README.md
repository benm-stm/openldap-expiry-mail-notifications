# openldap-expiry-mail-notifications

This small perl script can check users with password policy, it checks the remaining days for users password expiry and notify them, it also bypass users with noexpire flag (like a whitelist).

#How to crone

30 0 * * * cd /home/bgzuser/openldap_password_expiry_notification && perl password_expiry_mail_notification.pl

Enjoy
