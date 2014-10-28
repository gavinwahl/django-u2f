Django U2F
----------

django-u2f provides support for FIDO U2F security tokens in Django

Installation
============

Add ``django_u2f`` to ``INSTALLED_APPS`` and include ``django_u2f.urls``
somewhere in your url patterns. Make sure that django's built in login view
does not not have a urlpattern, because it will authenticate users without
their second factor. django-u2f provides its own login view to handle that.

Demo
====

To see a demo, use the test project included in the repo. Install django-u2f
with ``pip install -e .``, then install the demo-specific requirements with
``cd testproj; pip install -r requirements.txt``. Run syncdb and create a user,
then start runserver.

For now, it's required to use a chrome version greater than 38, and
install an extension. The chrome extension only works on domains that
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


Helpful links
=============

- The code to actually implement the crypto in python:
  https://github.com/Yubico/python-u2flib-server
- The Chrome extension, unfortunately required for the time being:
  https://chrome.google.com/webstore/detail/fido-u2f-universal-2nd-fa/pfboblefjcgdjicmnffhdgionmgcdmne
- A description of the process from a developer's perspective from Yubico:
  https://developers.yubico.com/U2F/Libraries/Using_a_library.html
