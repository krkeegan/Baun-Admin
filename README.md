# Baun Admin

The Admin plugin for Baun gives you a familiar web-based editor for managing your content. Login and
edit pages & posts from anywhere in the world. [Find out more](http://bauncms.com/plugins/admin).

# KRKeegan Fork

This is a fork from the original [Baun Admin](https://github.com/BaunCMS/Baun-Admin)
plugin.  I have added features that I find useful.  These include:

* User defined header keys as inputs in the 'simple' editor interface such as
'exclude_from_nav' or 'template'.  Keys are defined in the admin.php config
file.
* UI Fixes (Show nav drop down on small screens, better alignment of view, edit,
and delete buttons)
* Allow for user defined slugs in the simple editor.  Necessary to editing any
index page as discovered by [ivoilic](https://github.com/ivoilic/Baun-Admin/commit/db02f4f19200e903a192fe61e8e29cdf5419f999)
* Enable image uploading from the Simple markdown editor. (Make sure you are
also using the [KRKeegan Fork of Baun CMS](https://github.com/krkeegan/Baun)
for this to work right.)
* Security Improvements - Don't report if username exists or not.  Add support
for fail2ban protection on login page.
* Fix bug preventing Folder field from being displayed properly.

## Fail2Ban

Add a the following to your apache-auth jail file in your fail2ban config:
```
[INCLUDES]
before = ../filter.d/apache-common.conf

[apache-auth]
enabled = true
failregex = %(known/failregex)s
            ^%(_apache_error_client)s (Baun-Admin Authentication Failure:).*(, referer: \S+)?\s*$

```
