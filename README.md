indieauth-clj
=============

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/indieauth-clj.svg)](https://clojars.org/dk.simongray/indieauth-clj)

This is a Clojure and ClojureScript implementation of
[IndieAuth](https://indieauth.spec.indieweb.org/), the profile of OAuth
2.0 with which people sign in to apps as their own website, e.g. to post
to it with Micropub. It covers both roles: the client, which signs a user
in, and the server, which authenticates the user and issues access
tokens.

- **The spec.** The code follows the Living Standard of 11 July 2024 and
  cites the section of each rule it implements. Its tests include the
  scenarios of the [indieauth.rocks](https://indieauth.rocks) test suite,
  run locally.
- **Plain data.** Requests, sessions and the data of a consent page are
  maps, and the endpoints are Ring handlers.
- **Nothing in the background.** Signing the user in at the server,
  the consent page and the storage of codes and tokens are yours.
- **Safe by default.** PKCE with S256 is required, a code works once and
  for a minute, tokens expire and are kept as hashes, a code or a refresh
  token used twice revokes its tokens, secrets are compared in constant
  time, and only the public internet is fetched.

The same code runs on the JVM, in Node and in the browser.

> This library was spun out of [indieblog](https://github.com/simongray/indieblog),
> the software of [simon.grays.blog](https://simon.grays.blog), which is its
> own IndieAuth server and signs its commenters in with theirs. Like
> indieblog, it was developed with assistance from frontier LLMs.

Getting started
---------------

It requires Clojure 1.11+ and Java 11+. For the latest release, add it
from [Clojars](https://clojars.org/dk.simongray/indieauth-clj) to the
`:deps` in your `deps.edn`:

```clojure
dk.simongray/indieauth-clj {:mvn/version "0.1.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead:

```clojure
dk.simongray/indieauth-clj
{:git/url "https://github.com/simongray/indieauth-clj"
 :git/sha "…"}
```

For ClojureScript, shadow-cljs only reads Git dependencies from
`deps.edn`, so also set `:deps true` in your `shadow-cljs.edn`. A function
that fetches gives a promise there. In a browser, a page that doesn't
allow other origins with CORS can't be read, so a client usually runs on
a server.

### Sign a user in

Find the server of the URL that the user typed with `discover!`:

```clojure
(require '[dk.simongray.indieauth :as indieauth])

(def discovery
  (indieauth/discover! "simon.grays.blog"))
;; => {:me                     "https://simon.grays.blog/"
;;     :urls                   ["https://simon.grays.blog/"]
;;     :metadata-url           "https://simon.grays.blog/auth/metadata"
;;     :metadata               {…}
;;     :issuer                 "https://simon.grays.blog/"
;;     :authorization-endpoint "https://simon.grays.blog/auth"
;;     :token-endpoint         "https://simon.grays.blog/auth/token"}
```

Then send the user's browser to the server with the URL of
`authorization-request`, and keep the session it gives you where the
browser's next request finds it, e.g. in your session store:

```clojure
(def request
  (indieauth/authorization-request discovery
                                   {:client-id    "https://app.example.net/"
                                    :redirect-uri "https://app.example.net/callback"
                                    :scope        "profile create"}))
;; => {:url     "https://simon.grays.blog/auth?response_type=code&client_id=…"
;;     :session {:state "…" :code-verifier "…" …}}
```

Without a scope, you get the user's profile URL alone. The browser comes
back to the redirect URL with the query parameters that `redeem!` takes,
along with the session:

```clojure
(indieauth/redeem! (:session request) query-params)
;; => {:me            "https://simon.grays.blog/"
;;     :access_token  "…"
;;     :token_type    "Bearer"
;;     :scope         "profile create"
;;     :expires_in    86400
;;     :refresh_token "…"
;;     :profile       {:name "Simon Gray" :url "https://simon.grays.blog/"}}
```

It checks the state and the issuer, redeems the code, and confirms that
the page of the `:me` names the same server, as section 5.4 asks. A
failure at any step gives a map of the `:error`, with its `:type` and
`:reason`. Use the session once for this, and keep it with the answer
if you'll use the token.

When the access token expires, after its `:expires_in` seconds,
`refresh!` exchanges the `:refresh_token` for a new one, and the new
answer's refresh token replaces the old. With the session and a token,
`userinfo!` reads the user's profile information again, and `revoke!`
revokes the token when the user signs out.

Serve your client metadata at the client identifier with
`client-metadata-handler`, so that servers can show your app's name and
logo, and list the redirect URLs on other hosts there.

If you'd rather keep nothing on the server, give `authorization-request`
a `:secret`. The state then carries the session, signed, and the
session's `:nonce` goes in a cookie, e.g. `HttpOnly` and `SameSite=Lax`.
At the redirect URL, `state-session` gets the session back from the state
and the cookie's nonce, so that only the browser that started a sign-in
can finish it.

### Run a server

A server consists of its Ring handlers, two stores and a function of
yours, `:authorize`, which signs the user in by any means and shows them
the consent page:

```clojure
(require '[dk.simongray.indieauth.server :as server])

(declare opts)

(defn authorize
  "The consent page of the authorization `request` for the user of the
  `ring-request`, or the sign-in page when nobody is signed in."
  [ring-request request]
  (if-let [me (signed-in-user ring-request)]
    (consent-page (server/consent request me opts))
    (sign-in-page (server/request-token request opts))))

(def opts
  {:issuer                 "https://simon.grays.blog/"
   :metadata-url           "https://simon.grays.blog/auth/metadata"
   :authorization-endpoint "https://simon.grays.blog/auth"
   :token-endpoint         "https://simon.grays.blog/auth/token"
   :revocation-endpoint    "https://simon.grays.blog/auth/revoke"
   :userinfo-endpoint      "https://simon.grays.blog/auth/userinfo"
   :scopes-supported       ["profile" "email" "create" "update" "delete"]
   :secret                 (indieauth/token)
   :codes                  (server/memory-store)
   :tokens                 (server/memory-store)
   :authorize              authorize})
```

Serve each endpoint with its handler: `server/handler` for the
authorization endpoint, and `token-handler`, `revocation-handler`,
`userinfo-handler` and `metadata-handler` for the others, each of `opts`.
Name them on the user's pages with the links of `server/links` or
`server/link-header`. Keep the `:secret`, a text of 32 bytes or more, so
that a restart doesn't void the sign-ins under way.

The handler checks the client's request before `authorize` gets it, and
`request-token` carries it through your sign-in pages. The consent page
names the client and lists the scopes that `consent` gives, and its form
posts back the `:token`, which is signed for that user alone. When the
user says yes, send the browser on to the redirect of `approve!`:

```clojure
(server/approve! token {:me "https://simon.grays.blog/" :scopes ["create"]} opts)
;; => {:redirect "https://app.example.net/callback?code=…&state=…&iss=…"}
```

The client's code works once, for a minute, and the token handler gives
it an access token, which lasts a day, and a refresh token, which lasts
30 days unused. When the user says no, send the browser to the URL of
`server/denial`. A store is a map of a few functions, so one for a
database takes a few lines, and `server/memory-store` describes them.
The options that have defaults, e.g. those lifetimes, are in
`server/default-options`.

### Check a token

A resource server in the same process, e.g. a Micropub endpoint, checks
the token of a request with `access!`:

```clojure
(server/access! ring-request ["create"] opts)
;; => {:me        "https://simon.grays.blog/"
;;     :client-id "https://app.example.net/"
;;     :scope     "create"
;;     :issued-at #inst "2026-10-11T12:00:00Z"
;;     :expires   #inst "2026-10-12T12:00:00Z"
;;     :grant     "…"}
```

When the token is missing, unknown or lacks the scope, it gives the
`:error` and the Ring `:response` to answer with.

A resource server in another process asks the server's introspection
endpoint instead. Serve `introspection-handler` with the
`:resource-tokens` that resource servers may ask with, and give
`access!` the `:introspection-endpoint` and one `:resource-token` in place
of the `:tokens`.

Principles
----------

- **Standards first.** The code follows the Living Standard and cites
  its sections, and a comment marks each choice of its own. Most rules
  are options too, and `indieauth/default-options` and
  `server/default-options` list their defaults, which follow the spec.
- **Plain data.** Sessions, requests and grants are maps, documents of
  the spec keep the names of their JSON, and every function that sends
  takes a `:send` of your own.
- **One codebase.** The library is written in `.cljc` and depends on
  [wary-fetch](https://github.com/simongray/wary-fetch) for requests,
  [html-pieces](https://github.com/simongray/html-pieces) for pages and
  [microformats-clj](https://github.com/simongray/microformats-clj) for
  h-cards and h-apps.

Development
-----------

```bash
clojure -X:test                       # the tests on the JVM
npm install                           # once, for the Node tests
clojure -M:cljs compile test          # the tests in Node
clojure -M:cljs compile browser-test  # for a browser, from target/browser-test
```

On the JVM, a test also signs a user in at a server of this library over
HTTP on localhost. [doc/indieauth-rocks.md](doc/indieauth-rocks.md) says
which scenarios of indieauth.rocks the tests cover, and how to run the
suite itself.

License
-------

The indieauth-clj project is licensed under the [MIT licence](LICENSE).
