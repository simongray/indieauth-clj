(ns ^:no-doc dk.simongray.indieauth.identifier
  "The parts of a URL as RFC 3986 reads them, and the rules that the
  identifiers of IndieAuth are made of: those of users, clients and
  servers, which dk.simongray.indieauth checks."
  (:require [clojure.string :as str]
            [dk.simongray.wary-fetch.url :as url]))

;; RFC 3986, appendix B
(defn url-parts
  "The parts of the URL `s` as a map of :scheme, :authority, :userinfo,
  :host, :port, :path, :query and :fragment, each nil when the URL has
  none, or nil when `s` has no scheme. The scheme is in lower case."
  [s]
  (when-let [[_ scheme authority path query fragment]
             (re-matches #"(?s)([a-zA-Z][a-zA-Z0-9+.\-]*):(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?"
                         (str s))]
    (let [[_ userinfo host port] (some->> authority
                                          (re-matches #"(?s)(?:(.*)@)?(\[[^\]]*\]|[^:]*)(?::(.*))?"))]
      {:scheme    (str/lower-case scheme)
       :authority authority
       :userinfo  userinfo
       :host      host
       :port      port
       :path      path
       :query     query
       :fragment  fragment})))

(def unsafe-characters
  "The characters that a URL of IndieAuth never has as they are: spaces,
  control characters and backslashes, which a browser reads otherwise."
  #"[\x00-\x20\x7f\\]")

(def default-ports
  "The port of each scheme of the web, which a canonical URL leaves out."
  {"http" "80" "https" "443"})

(def loopback-hosts
  "The IP addresses that a client identifier may have as its host."
  #{"127.0.0.1" "[::1]"})

;; IndieAuth 3.4: a host alone is a URL
(defn with-scheme
  "The text `s` with https:// in front, unless it has a scheme, as people
  write a host alone in a sign-in form."
  [s]
  (if (or (re-find #"(?i)^https?://" s)
          (re-find #"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!\d)" s))
    s
    (str "https://" s)))

(defn domain-name?
  "Whether the `host` of a URL is a domain name: labels between dots, of
  characters that a host may have, and not an IP address, which a host
  that ends in a number is, as a browser reads it."
  [host]
  (let [h (str/replace (str/lower-case host) #"\.$" "")]
    (boolean (and (re-matches #"[^\x00-\x20\x7f#%/:<>?@\[\\\]^|]+" h)
                  (every? seq (str/split h #"\." -1))
                  (not (re-find #"(^|\.)(\d+|0x[0-9a-f]*)$" h))
                  (nil? (url/ip-address h))))))

(defn port?
  "Whether the text `s` is the number of a port."
  [s]
  (boolean (some-> (re-matches #"\d{1,5}" s) parse-long (<= 65535))))

(defn- dot-segment?
  "Whether the path `segment` is . or .., also when percent-encoded, as a
  browser reads it."
  [segment]
  (boolean (re-matches #"(?i)(\.|%2e){1,2}" segment)))

;; IndieAuth 3.2 and 3.3, with an empty path as /, as section 3.4 has it
(defn parts
  "The parts of `s` as url-parts gives them, if it passes the rules that
  profile URLs and client identifiers share: an http or https URL with a
  host, and without a fragment, a user name, a password, a . or ..
  segment in its path, or a character of unsafe-characters. Else nil."
  [s]
  (when (and (string? s) (not (re-find unsafe-characters s)))
    (let [{:keys [scheme userinfo host path fragment] :as parts} (url-parts s)]
      (when (and (#{"http" "https"} scheme)
                 (seq host)
                 (nil? userinfo)
                 (nil? fragment)
                 (not-any? dot-segment? (str/split path #"/")))
        parts))))

;; IndieAuth 4.2: a client on a loopback host isn't fetched
(defn loopback?
  "Whether the URL `s` names a loopback host: 127.0.0.1, [::1] or
  localhost."
  [s]
  (let [host (:host (url-parts s))]
    (boolean (or (contains? loopback-hosts host)
                 (re-find #"(?i)(^|\.)localhost\.?$" (str host))))))
