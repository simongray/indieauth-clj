(ns dk.simongray.indieauth.state
  "The state of an authorization request and the PKCE code verifier that
  goes with it: random, or with a secret, a state that carries the
  session, signed, and that a nonce ties to the browser.

  The kind of a state is a keyword of its sign-in protocol, e.g.
  :dk.simongray.indieauth/session, so that under a shared secret the
  state of one protocol never passes for that of another."
  (:require [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.wary-fetch.bytes :as bytes]))

(defn- random-text
  "A text of 32 random bytes in the URL-safe letters of base64."
  []
  (bytes/base64url (bytes/random 32)))

(defn- verifier
  "The PKCE code verifier of the signed `state`, which only the `secret`
  gives."
  [secret state]
  (signed/derive-text secret "code_verifier" state))

;; IndieAuth 5.2.1: the state can hold the session; RFC 9700, section
;; 4.7.1: a state that is bound to the browser
(defn fresh
  "The :state and the PKCE :code-verifier of the `session`, and with a
  `secret`, the :nonce of a state of the `kind` that carries the session,
  signed at the instant `at`.

  Keep the nonce where only the user's browser has it, e.g. in a cookie,
  and give it to session with the state when the browser comes back.
  Without a secret, the state is random and carries nothing."
  [secret kind session at]
  (if secret
    (let [nonce (random-text)
          state (signed/sign secret kind
                             (assoc session :nonce (digest/text nonce))
                             at)]
      {:state state :code-verifier (verifier secret state) :nonce nonce})
    {:state (random-text) :code-verifier (random-text)}))

(defn session
  "The session that the `state` of the `kind` carries, by the `secret`, if
  the `nonce` is the session's, and the state was signed at most
  `max-seconds` before the instant `at`, or else nil. The session has its
  :nonce, :state and :code-verifier too."
  [secret kind state nonce at max-seconds]
  (let [m (signed/unsign secret kind state at max-seconds)]
    (when (and m
               (string? nonce)
               (bytes/same-text? (digest/text nonce) (:nonce m)))
      (assoc m
             :nonce         nonce
             :state         state
             :code-verifier (verifier secret state)))))
