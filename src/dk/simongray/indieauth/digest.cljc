(ns ^:no-doc dk.simongray.indieauth.digest
  "The digests that stand in for secret texts, so that a client or a
  server can keep or compare them without the texts themselves."
  (:require [dk.simongray.webcrypto.bytes :as bytes]
            [dk.simongray.webcrypto.hash :as hash]))

(defn text
  "The SHA-256 of the text `s` in the URL-safe letters of base64, e.g. a
  PKCE code challenge, or the key under which a store keeps a token."
  [s]
  (bytes/base64url (hash/digest :sha-256 (bytes/encode (str s)))))
