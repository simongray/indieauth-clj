indieauth.rocks
===============

[indieauth.rocks](https://indieauth.rocks) tests IndieAuth servers and
clients over the internet: it's the client of your server, or the server
of your client, and some of its servers misbehave on purpose. The tests
of this library reproduce its scenarios locally, with the sites of each
scenario as Ring handlers in memory, so that they run in CI on both
platforms. A test names each scenario by its number, e.g. C103.

The scenarios that the tests don't cover are those that depend on how
you deploy and render, and those of tokens that the library doesn't
issue.

Covered
-------

- **Client:** C101 to C112 (discovery), C201 to C210 (the authorization
  request), C301 to C306 (the callback), C401 to C410 (redemption and the
  confirmation of the me) and C501 to C505 (tokens), in
  `indieauth_test.cljc`. C307, a replayed answer, holds when you use each
  session once, as the end-to-end test does.
- **Server:** S104 to S115 and S117 (metadata), S201 to S222 but S206
  (the authorization request), S301 to S334 but S322 (redemption), S401
  to S410 (the token response), S501 to S505 (refresh tokens), S601 to
  S604 (revocation), S701 to S703 (userinfo) and S801 to S804
  (introspection), in `server_test.cljc`. S304 and the lifetimes of tokens
  run with a clock of the test's own rather than waiting. S902, S905 and
  S906 hold for the library's own answers.

Not covered
-----------

- **Your deployment:** S101 to S103 test your profile page, S116 and S901
  that your endpoints use https, and S902 the headers of your sign-in and
  consent pages, for which `server/page-headers` has the headers to add.
- **Your pages:** S206, what your consent page shows.
- **Not this library's tokens:** S420 to S423 test JWT access tokens,
  and the library's are random texts. S322 tests a code issued without
  PKCE, which the library never issues.

Run the suite by hand
---------------------

The suite needs your server or your client on a public https URL, and
you at a browser to approve or cancel some steps.

To test a server, serve the endpoints of `server/handler`,
`token-handler`, `revocation-handler`, `introspection-handler`,
`userinfo-handler` and `metadata-handler`, and name them on your profile
page with `server/links`. Enter the profile URL at
https://indieauth.rocks and follow the steps, signing in and approving
at your consent page when the suite asks. The extended run also waits 11
minutes to test that a code expires, and asks for one of your
`:resource-tokens` to test introspection.

To test a client, serve an app that signs users in with `discover!`,
`authorization-request` and `redeem!`, and its client metadata with
`client-metadata-handler`. Sign in to https://indieauth.rocks/sign-in with
your own website, and then sign in to your app with each profile URL
that the suite gives you. Its tokens expire after two minutes, to test
that the app refreshes them with `refresh!`.

Neither has been run against the live suite yet, since that needs a
deployment.
