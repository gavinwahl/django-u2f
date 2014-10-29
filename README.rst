Django U2F
----------

django-u2f provides support for FIDO U2F security tokens in Django.

django-u2f isn't yet production ready, but is a working proof of
concept. There are many TODOs sprinkled around the code that should be
fixed before relying on it.

Installation
============

Add ``django_u2f`` to ``INSTALLED_APPS`` and include
``django_u2f.urls`` somewhere in your url patterns. Set ``LOGIN_URL
= 'django_u2f.views.login'``. Make sure that Django's built in login
view does not not have a urlpattern, because it will authenticate users
without their second factor. django-u2f provides its own login view to
handle that.

Demo
====

To see a demo, use the test project included in the repo. Install django-u2f
with ``pip install -e .``, then install the demo-specific requirements with
``cd testproj; pip install -r requirements.txt``. Run syncdb and create a user,
then start runserver.

For now, it's required to use a Chrome version greater than 38, and
install an extension. The Chrome extension only works on domains that
have a dot in them, so you can't use ``localhost``, but instead an alias
for 127.0.0.1 in your hosts file. I used ``localhost.com``.


Start by going to http://localhost.com:8000/u2f/login. Since you
haven't added any security keys yet, you will be logged in with just a
username and password. Once logged in, click 'Add another key' on the
key management page and follow the instructions. Now your account is
protected by two factor authentication, and when you log in again your
U2F token will be required.

You can administrate the keys attached to your account on the key
management page as well, at the URL ``/u2f/keys``.

Using U2F keys on linux
=======================

Some distros don't come with udev rules to make USB HID /dev/
nodes accessible to normal users. If your key doesn't light up
and start flashing when you expect it to, this might be what is
happening. See https://github.com/Yubico/libu2f-host/issues/2 and
https://github.com/Yubico/libu2f-host/blob/master/70-u2f.rules for some
discussion of the rule to make it accessible. If you just want a quick
temporary fix, you can run ``sudo chmod 666 /dev/hidraw*`` every time
after you plug in your key (The files disappear after unplugging).


Helpful links
=============

- The code to actually implement the crypto in python:
  https://github.com/Yubico/python-u2flib-server
- The Chrome extension, unfortunately required for the time being:
  https://chrome.google.com/webstore/detail/fido-u2f-universal-2nd-fa/pfboblefjcgdjicmnffhdgionmgcdmne
- A description of the process from a developer's perspective from Yubico:
  https://developers.yubico.com/U2F/Libraries/Using_a_library.html
