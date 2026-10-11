(ns ^:no-doc dk.simongray.indieauth.bytes
  "Bytes on both platforms: a byte array on the JVM, and a Uint8Array in
  JavaScript, with the hashes, HMACs and randomness that IndieAuth needs.

  The hashes are synchronous on both platforms. In JavaScript they come
  from the Closure Library rather than WebCrypto, whose digests only come
  as promises."
  #?(:cljs (:require [goog.crypt.base64 :as base64]
                     [goog.crypt.Hmac]
                     [goog.crypt.Sha256]))
  #?(:clj (:import [java.nio.charset StandardCharsets]
                   [java.security MessageDigest SecureRandom]
                   [java.util Base64]
                   [javax.crypto Mac]
                   [javax.crypto.spec SecretKeySpec])))

(defn encode
  "The bytes of the text `s` in UTF-8."
  [s]
  #?(:clj  (.getBytes (str s) StandardCharsets/UTF_8)
     :cljs (.encode (js/TextEncoder.) (str s))))

(defn decode
  "The text of the bytes `b` in UTF-8."
  [b]
  #?(:clj  (String. ^bytes b StandardCharsets/UTF_8)
     :cljs (.decode (js/TextDecoder.) b)))

(defn length
  "The number of bytes in `b`."
  [b]
  #?(:clj  (alength ^bytes b)
     :cljs (.-length b)))

(defn same?
  "Whether the bytes `a` and `b` are the same, in a time that doesn't tell
  where they differ."
  [a b]
  #?(:clj  (MessageDigest/isEqual ^bytes a ^bytes b)
     :cljs (and (= (alength a) (alength b))
                (zero? (areduce a i acc 0
                                (bit-or acc (bit-xor (aget a i) (aget b i))))))))

(defn same-text?
  "Whether `a` and `b` are the same text, in a time that doesn't tell where
  they differ. Nil or another value is never the same."
  [a b]
  (and (string? a)
       (string? b)
       (same? (encode a) (encode b))))

(defn random
  "`n` random bytes from the platform's secure source."
  [n]
  #?(:clj  (let [b (byte-array n)]
             (.nextBytes (SecureRandom.) b)
             b)
     :cljs (js/crypto.getRandomValues (js/Uint8Array. n))))

;; RFC 4648, section 5
(defn base64url
  "The bytes `b` in the URL-safe alphabet of base64, without padding."
  [b]
  #?(:clj  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) b)
     :cljs (base64/encodeByteArray b base64/Alphabet.WEBSAFE_NO_PADDING)))

(defn random-text
  "`n` random bytes from the platform's secure source, in the URL-safe
  letters of base64."
  [n]
  (base64url (random n)))

(defn unbase64url
  "The bytes of the text `s` in the URL-safe alphabet of base64, without
  padding, or nil when it isn't."
  [s]
  (when (and (string? s) (re-matches #"[A-Za-z0-9_-]*" s))
    (try
      #?(:clj  (.decode (Base64/getUrlDecoder) ^String s)
         :cljs (base64/decodeStringToUint8Array s))
      (catch #?(:clj Exception :cljs :default) _
        nil))))

;; FIPS 180-4
(defn sha256
  "The SHA-256 digest of the bytes `b`, as bytes."
  [b]
  #?(:clj  (.digest (MessageDigest/getInstance "SHA-256") ^bytes b)
     :cljs (let [h (goog.crypt.Sha256.)]
             (.update h b)
             (js/Uint8Array.from (.digest h)))))

(defn hash-text
  "The SHA-256 of the text `s` in the URL-safe letters of base64, e.g. a
  PKCE code challenge, or the key under which a store keeps a token."
  [s]
  (base64url (sha256 (encode s))))

;; RFC 2104
(defn hmac-sha256
  "The HMAC-SHA256 of the bytes `message` with the bytes `key`, as bytes."
  [key message]
  #?(:clj  (.doFinal (doto (Mac/getInstance "HmacSHA256")
                       (.init (SecretKeySpec. ^bytes key "HmacSHA256")))
                     ^bytes message)
     :cljs (let [mac (goog.crypt.Hmac. (goog.crypt.Sha256.) (js/Array.from key) 64)]
             (js/Uint8Array.from (.getHmac mac message)))))
