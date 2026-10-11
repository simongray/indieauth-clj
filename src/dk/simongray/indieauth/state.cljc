(ns dk.simongray.indieauth.state
  "The state of an authorization request and the PKCE code verifier that
  goes with it, and with a secret, a cookie that carries the session,
  signed, and ties the state to the browser.

  The state is random and short whatever the session holds, since it
  travels in a URL, which a provider may limit and logs. The kind of a
  cookie is a keyword of its sign-in protocol, e.g.
  :dk.simongray.indieauth/session, so that under a shared secret the
  cookie of one protocol never passes for that of another."
  (:require [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.wary-fetch.bytes :as bytes]))

;; RFC 6265, section 6.1: a browser keeps a cookie of 4096 bytes at least
(def max-cookie-bytes
  "The size of the largest cookie that fresh gives by default, which
  leaves room for the cookie's name within the 4096 bytes of a browser."
  3500)

(defn- random-text
  "A text of 32 random bytes in the URL-safe letters of base64."
  []
  (bytes/base64url (bytes/random 32)))

(defn- verifier
  "The PKCE code verifier of the `state`, which only the `secret` gives."
  [secret state]
  (signed/derive-text secret "code_verifier" state))

;; RFC 9700, section 4.7.1: a state that is bound to the browser
(defn fresh
  "The random :state and the PKCE :code-verifier of the `session`, and
  with a `secret`, the :cookie of the `kind` that carries the session and
  the state, signed at the instant `at`.

  Keep the cookie where only the user's browser has it, e.g. in an
  HttpOnly cookie, and give it to session with the state when the browser
  comes back. A cookie of more than `max-bytes`, max-cookie-bytes by
  default, throws, since a browser drops a cookie that's too large without
  a word."
  ([secret kind session at]
   (fresh secret kind session at max-cookie-bytes))
  ([secret kind session at max-bytes]
   (let [state (random-text)]
     (if secret
       (let [cookie (signed/sign secret kind (assoc session :state state) at)]
         (when (< max-bytes (count cookie))
           (throw (ex-info (str "The signed session takes " (count cookie)
                                " bytes, more than the " max-bytes
                                " of a cookie, e.g. for a large :data")
                           {:bytes (count cookie) :max-bytes max-bytes})))
         {:state state :code-verifier (verifier secret state) :cookie cookie})
       {:state state :code-verifier (random-text)}))))

(defn session
  "The session that the `cookie` of the `kind` carries, by the `secret`, if
  its state is the `state` that came back, and it was signed at most
  `max-seconds` before the instant `at`, or else nil. The session has its
  :state, :code-verifier and :cookie too."
  [secret kind state cookie at max-seconds]
  (let [m (signed/unsign secret kind cookie at max-seconds)]
    (when (and m (bytes/same-text? (:state m) state))
      (assoc m
             :cookie        cookie
             :code-verifier (verifier secret state)))))
