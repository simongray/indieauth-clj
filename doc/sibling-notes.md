Sibling notes
=============

What indieauth-clj needed from wary-fetch, html-pieces and
microformats-clj, what it did instead, and what those libraries could
offer, so that websub-clj, webmention-clj, a future micropub-clj and this
library stop writing the same code.

Endpoint discovery
------------------

**Needed:** the URLs that a response names by a relation type, the Link
headers first and then the link elements of the page. IndieAuth finds
its metadata this way (section 4.1), a client's redirect URLs (4.2.2) and
the older endpoints. Webmention, Micropub and WebSub find theirs the same
way.

**Did instead:** `dk.simongray.indieauth.links`, which holds nothing of
IndieAuth's own. It reads the head of a page as a browser does, with its
base, as websub-clj's `document.cljc` does, so the two have the same code
now. It reads link elements in the head alone: indieauth.rocks's C112
puts a decoy in the body, where anyone who comments can write. It takes
the Hiccup of html-pieces, so a page is parsed once for its links and its
microformats.

**Could offer:** the protocols differ in where they look. Webmention
takes the first link or a element with rel=webmention anywhere in the
document, while IndieAuth and WebSub want link elements, best in the
head. So the shared function takes the elements and whether the body
counts as options. I'd put it in html-pieces, since the head, the base
and the elements are HTML's rules, as `links` of parsed nodes, by tags
and :body?. wary-fetch already has the other half in `headers/links`,
and putting the header links first is a line each library can keep. It
doesn't belong in microformats-clj, whose rels are those of a and link
elements anywhere, which suits Webmention but would let a decoy in the
body win in IndieAuth.

wary-fetch
----------

- **Hashes and randomness.** Needed SHA-256, HMAC-SHA256, secure random
  bytes, base64url both ways and a comparison in constant time,
  synchronous on both platforms. Did instead: `indieauth/bytes.cljc`, a
  copy of websub-clj's `bytes.cljc` with SHA-256 and decoding added, on
  the Closure Library in JavaScript. Could offer: these in
  `wary-fetch.bytes`, which has base64 already, since both libraries
  copy them, and wary-fetch's hidden texts are already about secrets.
- **JSON.** Needed to read and write JSON on both platforms: metadata,
  client metadata and token responses. Did instead: `indieauth/json.cljc`
  over data.json on the JVM, a new dependency, and `JSON` in JavaScript.
  Could offer: `:as :json` for a response, since IndieAuth, Micropub and
  Microsub all read JSON, and each library would otherwise add the same
  dependency.
- **Repeated parameters.** Needed to refuse a parameter that comes twice
  (RFC 6749, section 3.1, and indieauth.rocks's S213), where
  `url/query-params` keeps the last value. Did instead: `ring/fields`,
  as pairs, as websub-clj's `ring.cljc` does. Could offer:
  `url/query-pairs`.
- **The parts of a URL.** Needed the parts as written, before a parser
  tidies them: whether a URL has a port, a user name, a fragment, or a
  `..` segment, also percent-encoded. Did instead: `indieauth/url-parts`,
  by RFC 3986, appendix B, with the host, port and user information of
  the authority. Could offer: `url/parts`, beside `origin` and `host`.
- **Ring helpers.** Needed the bytes of a request's body up to a limit, a
  form as pairs, plain and JSON answers, and a handler built from a map
  of request methods, whose 405 lists them, and whose functions can give
  promises in ClojureScript. Did instead: `indieauth/ring.cljc`,
  grown from websub-clj's `ring.cljc`. Webmention's receiving endpoint
  needs the same. Could offer: a `wary-fetch.ring` for the server side of
  a request, if that fits wary-fetch's purpose; else a small library of
  its own.
- **Redirects in a browser.** Section 5.4 accepts a returned me that
  discovery went through, and wary-fetch lists the redirects on the JVM
  and in Node. In a browser, fetch hides them, so a client there fetches
  the me once more instead, which needs no change.

html-pieces
-----------

- **The head of a page.** Needed the elements that a browser puts in the
  head, also in a page without a head tag, and the base of the page.
  Did instead: `links/head`, copied from websub-clj. Could offer: `head`
  and `base-url` of parsed nodes, and the `links` above.

microformats-clj
----------------

- **The representative h-card.** Needed the h-card of a user's page for
  the profile information of section 5.3.4. Did instead: the algorithm
  of the microformats wiki in `server/representative-card`, over the
  :items and the rel=me of `parse`. indieblog does the same for its
  commenters, and Webmention's authorship algorithm starts there too.
  Could offer: `representative-card`, and the authorship algorithm.
- **A property's value.** Needed the first value of a property as a text,
  where a u-photo can be a map of :value and :alt. Did instead: a private
  `property`. Could offer: a `value` helper.
- **h-app.** The legacy client information is an h-app or h-x-app,
  which `parse` reads fine.
