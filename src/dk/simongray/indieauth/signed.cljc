(ns ^:no-doc dk.simongray.indieauth.signed
  "Maps signed with a secret into a URL-safe text, so that a value can make
  a round trip through a browser and come back unchanged, with nothing
  stored. Each signed map has a kind, so that one kind never passes for
  another, and the instant it was signed, so that it expires."
  (:require #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.wary-fetch.secret :as secret]))

(defn- key-bytes
  "The bytes of the text `secret`, which can be a hidden text, or a throw
  when it has fewer than 32 bytes."
  [secret]
  (let [b (bytes/encode (secret/reveal secret))]
    (when (< (bytes/length b) 32)
      (throw (ex-info "A secret has 32 bytes at least, e.g. a token" {})))
    b))

(defn- signature
  "The signature of the text `s` with the `secret`, as bytes."
  [secret s]
  (bytes/hmac-sha256 (key-bytes secret) (bytes/encode s)))

(defn- edn-text
  "The value `x` as EDN, printed in full."
  [x]
  (binding [*print-length*         nil
            *print-level*          nil
            *print-meta*           false
            *print-namespace-maps* false]
    (pr-str x)))

(defn sign
  "The map `m` of `kind`, a keyword, signed with the `secret` at the
  instant `at`, as a URL-safe text."
  [secret kind m at]
  (let [payload (-> [kind (inst-ms at) m]
                    edn-text
                    bytes/encode
                    bytes/base64url)]
    (str payload "." (bytes/base64url (signature secret payload)))))

(defn- payload-value
  "The kind, instant and map in the `payload` of a signed text as a
  vector, or nil when it holds none."
  [payload]
  (try
    (let [[kind at m :as x] (some-> (bytes/unbase64url payload)
                                    bytes/decode
                                    edn/read-string)]
      (when (and (vector? x) (keyword? kind) (int? at) (map? m))
        x))
    (catch #?(:clj Exception :cljs :default) _
      nil)))

(defn unsign
  "The map of `kind` that the text `s` holds, if the `secret` signed it at
  most `max-seconds` before the instant `at`, or nil."
  [secret kind s at max-seconds]
  (when-let [[_ payload sig] (and (string? s)
                                  (re-matches #"([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)"
                                              s))]
    (let [given (bytes/unbase64url sig)]
      ;; only a map that the secret signed is read
      (when (and given (bytes/same? (signature secret payload) given))
        (let [[signed-kind signed-at m] (payload-value payload)]
          (when (and (= kind signed-kind)
                     (<= 0 (- (inst-ms at) signed-at) (* 1000 max-seconds)))
            m))))))

(defn derive-text
  "A URL-safe text that only the `secret` gives for the text `s` and the
  `purpose`, e.g. the PKCE verifier of a signed state."
  [secret purpose s]
  (bytes/base64url (signature secret (str purpose ":" s))))
