(ns ^:no-doc dk.simongray.indieauth.digest
  "The digests that stand in for secret texts, so that a client or a
  server can keep or compare them without the texts themselves."
  (:require [dk.simongray.wary-fetch.bytes :as bytes]))

(defn text
  "The SHA-256 of the text `s` in the URL-safe letters of base64, e.g. a
  PKCE code challenge, or the key under which a store keeps a token."
  [s]
  (bytes/base64url (bytes/digest :sha256 (bytes/encode s))))
