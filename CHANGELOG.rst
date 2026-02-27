2.0.0 (unreleased)
------------------

- Remove support for python<3.9
- Upgrade to webauthn 2.0
- Use native browser WebAuthn JSON serialization APIs. Requires Baseline 2025
  browser support.
- JSON API delete endpoints return 204 No Content instead of a JSON null body.
- Remove dead U2FKey.to_json() method left over from u2flib migration.
- Fix get_rp_id stripping wrong characters from hostnames containing port digits.
- Use site name for rp_name and username for user_name in WebAuthn registration.
- Set user_verification to discouraged during registration (unnecessary for 2FA).


1.0.1 (2022-08-08)
------------------

- Bug fixes for Django 2.2


1.0.0 (2022-01-14)
------------------

- Start using the WebAuthn API instead of u2f.


0.3.0 (2018-04-24)
------------------

- Allow overriding the view used for admin login in monkeypatch_admin.


0.2.0 (2017-05-22)
------------------
- Django 1.11 support, remove 1.8 support.
- python-u2flib-server 5.0 support.
- Slightly better default templates.

0.1.0 (2016-04-15)
------------------

Initial release.
