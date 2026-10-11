Sibling notes
=============

What indieauth-clj takes from wary-fetch, html-pieces and
microformats-clj, and what it still does itself, so that websub-clj,
webmention-clj, relmeauth-clj and this library don't write the same code.

Taken from the siblings
-----------------------

Since wary-fetch 0.3.0, html-pieces 0.4.1 and microformats-clj 0.2.0,
indieauth-clj keeps no copies of their code:

- **wary-fetch:** bytes, hashes and HMACs, JSON, the parts of a URL as
  written, query parameters as pairs, so that a repeated one can be
  refused (RFC 6749, section 3.1), and form requests with a hidden body.
- **html-pieces:** the link elements of a page, in its head alone, as
  indieauth.rocks's C112 asks, with the base from the head too, since
  anyone who writes in the body could add a base element there.
- **microformats-clj:** the representative h-card and the values of
  properties.

Still its own
-------------

- **Ring.** The requests and answers of the endpoints are in `ring.cljc`,
  since wary-fetch keeps to the client's side. Webmention's receiving
  endpoint needs the same, so a small library could hold them one day.
- **Two compositions.** `digest/text` is the SHA-256 of a text in
  base64url, and `fetch/json-object` a JSON object or nil. Each is a
  line or two.
- **Redirects in a browser.** Section 5.4 accepts a returned me that
  discovery went through, and wary-fetch lists the redirects on the JVM
  and in Node. In a browser, fetch hides them, so a client there fetches
  the me once more instead, which needs no change.
