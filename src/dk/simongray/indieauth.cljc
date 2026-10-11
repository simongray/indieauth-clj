(ns dk.simongray.indieauth
  "IndieAuth for clients: the identifiers of users, clients and servers,
  the discovery of a user's server, and signing in with it, with an access
  token or without.

  The code follows the IndieAuth Living Standard of 11 July 2024 at
  https://indieauth.spec.indieweb.org/ and cites its sections. The server
  is in dk.simongray.indieauth.server."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.links :as links]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

;; RFC 3986, appendix B
(defn ^:no-doc url-parts
  "The parts of the URL `s` as a map of :scheme, :authority, :path, :query
  and :fragment, each nil when the URL has none, or nil when `s` has no
  scheme. The scheme is in lower case."
  [s]
  (when-let [[_ scheme _ authority path _ query _ fragment]
             (re-matches #"(?s)([a-zA-Z][a-zA-Z0-9+.\-]*):(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?"
                         (str s))]
    {:scheme    (str/lower-case scheme)
     :authority authority
     :path      path
     :query     query
     :fragment  fragment}))

(defn ^:no-doc authority-parts
  "The user information, host and port of the `authority` of a URL, as a
  map of :userinfo, :host and :port, each nil when it has none."
  [authority]
  (let [at       (str/last-index-of authority "@")
        userinfo (when at (subs authority 0 at))
        hostport (if at (subs authority (inc at)) authority)
        [_ host port] (re-matches #"(\[[^\]]*\]|[^:]*)(?::(.*))?" hostport)]
    {:userinfo userinfo
     :host     host
     :port     port}))

(defn- domain-name?
  "Whether the `host` of a URL is a domain name: labels between dots, of
  characters that a host may have, and not an IP address, which a host
  that ends in a number is, as a browser reads it."
  [host]
  (let [h (str/replace (str/lower-case host) #"\.$" "")]
    (boolean (and (re-matches #"[^\x00-\x20\x7f#%/:<>?@\[\\\]^|]+" h)
                  (every? seq (str/split h #"\." -1))
                  (not (re-find #"(^|\.)(\d+|0x[0-9a-f]*)$" h))
                  (nil? (url/ip-address h))))))

(defn- dot-segment?
  "Whether the path `segment` is . or .., also when percent-encoded, as a
  browser reads it."
  [segment]
  (boolean (re-matches #"(?i)(\.|%2e){1,2}" segment)))

(defn- identifier-problem
  "What's wrong with `s` as the URL of a user or a client, by the rules
  that both share, or nil. An empty path is /, as section 3.4 has it."
  [s]
  (let [{:keys [scheme authority path fragment]} (url-parts s)
        {:keys [userinfo host]} (some-> authority authority-parts)]
    (cond
      (not (string? s))                          "isn't a text"
      (re-find #"[\x00-\x20\x7f\\]" s)           "has a space, a control character or a backslash"
      (not (#{"http" "https"} scheme))           "isn't an http or https URL"
      (nil? authority)                           "has no host"
      (some dot-segment? (str/split path #"/"))  "has a . or .. path segment"
      (some? fragment)                           "has a fragment"
      (some? userinfo)                           "has a user name or a password"
      (empty? host)                              "has no host")))

;; IndieAuth 3.2
(defn profile-url?
  "Whether `s` is a valid profile URL of a user: an http or https URL with
  a domain name, without a port, a fragment, a user name or a password,
  or a . or .. segment in its path.

      (profile-url? \"https://example.com/users?id=100\") ;; => true
      (profile-url? \"https://example.com:8443/\")        ;; => false"
  [s]
  (boolean
   (when-not (identifier-problem s)
     (let [{:keys [host port]} (authority-parts (:authority (url-parts s)))]
       (and (nil? port)
            (domain-name? host))))))

(def ^:no-doc loopback-hosts
  "The IP addresses that a client identifier may have as its host."
  #{"127.0.0.1" "[::1]"})

;; IndieAuth 3.3
(defn client-id?
  "Whether `s` is a valid client identifier: an http or https URL with a
  domain name, 127.0.0.1 or [::1], without a fragment, a user name or a
  password, or a . or .. segment in its path. Unlike a profile URL, it
  can have a port."
  [s]
  (boolean
   (when-not (identifier-problem s)
     (let [{:keys [host port]} (authority-parts (:authority (url-parts s)))]
       (and (or (nil? port)
                (and (re-matches #"\d{1,5}" port) (<= (parse-long port) 65535)))
            (or (domain-name? host)
                (contains? loopback-hosts host)))))))

;; IndieAuth 3.1; RFC 9207, section 2
(defn issuer?
  "Whether `s` is a valid issuer identifier of a server: an https URL with
  a host, and without a query or a fragment."
  [s]
  (let [{:keys [scheme authority query fragment]} (url-parts s)]
    (boolean (and (string? s)
                  (= "https" scheme)
                  (seq (:host (some-> authority authority-parts)))
                  (nil? query)
                  (nil? fragment)
                  (not (re-find #"[\x00-\x20\x7f\\]" s))))))

;; RFC 8414, section 3.1
(defn well-known-url
  "The URL of the metadata of the server whose issuer identifier is
  `issuer`, at the well-known location of RFC 8414.

      (well-known-url \"https://example.com/indieauth/\")
      ;; => \"https://example.com/.well-known/oauth-authorization-server/indieauth\""
  [issuer]
  (let [{:keys [scheme authority path]} (url-parts issuer)]
    (str scheme "://" authority "/.well-known/oauth-authorization-server"
         (str/replace path #"/$" ""))))

;; IndieAuth 3.1 and 4.1.1
(defn issuer-of?
  "Whether the `issuer` identifier fits the URL of its metadata,
  `metadata-url`: a prefix of it that ends where a path segment ends, or
  the issuer whose well-known metadata it is."
  [issuer metadata-url]
  (let [issuer       (str issuer)
        metadata-url (str metadata-url)]
    (boolean
     (and (issuer? issuer)
          (or (= issuer metadata-url)
              (and (str/starts-with? metadata-url issuer)
                   (or (str/ends-with? issuer "/")
                       (#{\/ \?} (nth metadata-url (count issuer)))))
              (= metadata-url (well-known-url issuer)))))))

(def ^:no-doc default-ports
  "The port of each scheme of the web, which a canonical URL leaves out."
  {"http" "80" "https" "443"})

;; IndieAuth 3.4
(defn canonical-url
  "The URL that the text `s` names, in the canonical form that IndieAuth
  compares, or nil when it names no http or https URL.

  A host alone becomes an https URL, as people write it in a sign-in
  form. The scheme and the host are in lower case, a default port is left
  out, and an empty path is /. Nothing else changes, so the result can be
  a URL that isn't a valid profile URL.

      (canonical-url \"Example.com\") ;; => \"https://example.com/\""
  [s]
  (let [s    (str/trim (str s))
        s    (if (or (re-find #"(?i)^https?://" s)
                     (re-find #"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!\d)" s))
               s
               (str "https://" s))
        {:keys [scheme authority path query fragment]} (url-parts s)
        {:keys [userinfo host port]} (some-> authority authority-parts)]
    (when (and (#{"http" "https"} scheme) (seq host))
      (str scheme "://"
           (some-> userinfo (str "@"))
           (str/lower-case host)
           (when (and port (not= port (default-ports scheme)))
             (str ":" port))
           (if (empty? path) "/" path)
           (some->> query (str "?"))
           (some->> fragment (str "#"))))))

(defn token
  "A random text of `n` bytes, 32 by default, that nobody can guess, e.g.
  for a state, a secret or an access token. The bytes come from a secure
  source, and the text is in the URL-safe letters of base64."
  ([]
   (token 32))
  ([n]
   (bytes/base64url (bytes/random n))))

;; IndieAuth 5.2; RFC 7636, section 4.1
(defn code-verifier
  "A new PKCE code verifier: 43 random characters of the URL-safe letters
  of base64, from 32 random bytes."
  []
  (token 32))

;; RFC 7636, section 4.1
(defn code-verifier?
  "Whether `s` is a PKCE code verifier: 43 to 128 of the characters A-Z,
  a-z, 0-9, -, ., _ and ~."
  [s]
  (boolean (and (string? s) (re-matches #"[A-Za-z0-9._~-]{43,128}" s))))

;; IndieAuth 5.2; RFC 7636, section 4.2
(defn code-challenge
  "The S256 code challenge of the code `verifier`: its SHA-256 in the
  URL-safe letters of base64."
  [verifier]
  (bytes/base64url (bytes/sha256 (bytes/encode verifier))))

;; RFC 6749, section 3.3
(defn scopes
  "The scopes in the text `s`, a list separated by spaces, as a vector
  without repeats. It's empty when `s` is blank or nil, and nil when a
  scope has a character that a scope can't have."
  [s]
  (let [xs (remove empty? (str/split (str s) #" +"))]
    (when (every? #(re-matches #"[\x21\x23-\x5B\x5D-\x7E]+" %) xs)
      (vec (distinct xs)))))

(defn scope-text
  "The `scopes`, a collection of texts, as the text of a scope parameter,
  or nil for none."
  [scopes]
  (some->> (seq scopes) distinct (str/join " ")))

;; IndieAuth 5.3.4
(def profile-scopes
  "The scopes that ask for the user's profile information rather than for
  an access token: profile, and email, which comes with profile alone."
  #{"profile" "email"})

;; IndieAuth 5.3.4
(defn ^:no-doc profile-scope-problem
  "What's wrong with the profile scopes among `scopes`, or nil."
  [scopes]
  (when (and (some #{"email"} scopes) (not (some #{"profile"} scopes)))
    "The email scope comes with the profile scope alone"))

;; IndieAuth 5.3.1 and 5.3.3
(defn token-scope?
  "Whether the `scopes` ask for an access token: whether one of them asks
  for more than profile information."
  [scopes]
  (boolean (some (complement profile-scopes) scopes)))

(def default-options
  "The default of each option of a client that has one, which follows
  IndieAuth:

  - :profile-url-pred, profile-url?, the URLs that a user can sign in as,
    as section 3.2 has them
  - :body-links?, false: a page names its server in its head, since anyone
    who writes in its body could name another
  - :session-seconds, 600: how long a user has to sign in at the server,
    and how long a signed state lasts
  - :timeout-seconds, 10: the limit of each request
  - :max-redirects, 5: how many redirects discovery follows, the limit
    that section 4.1 asks a client to set
  - :max-page-bytes, 2 MB: the largest page of a profile URL
  - :max-json-bytes, 256 kB: the largest JSON document of a server
  - :send, http/send-public!, which sends to the public internet alone
  - :now-fn, a function that gives the instant now"
  {:profile-url-pred profile-url?
   :body-links?      false
   :session-seconds  600
   :timeout-seconds  10
   :max-redirects    5
   :max-page-bytes   (* 2 1024 1024)
   :max-json-bytes   (* 256 1024)
   :send             http/send-public!
   :now-fn           #?(:clj  #(java.util.Date.)
                        :cljs #(js/Date.))})

(defn- failure
  "A map of the :error of `type`, a keyword, with the `reason` and the facts
  of the map `m`."
  ([type reason]
   (failure type reason {}))
  ([type reason m]
   {:error (merge {:type type :reason reason} m)}))

(defn- fetch!
  "The response to a GET of `url` for the media types `accept`, with a body
  of `max-bytes` at most, by `opts`, or a map of the :error."
  [url accept max-bytes opts]
  (async/then (async/attempt
               #(http/fetch! url (assoc opts :accept accept :max-bytes max-bytes)))
              (fn [{:keys [value error]}]
                (cond
                  error
                  {:error (http/failure error)}

                  (not (<= 200 (:status value) 299))
                  (failure ::failed (str url " answered " (:status value))
                           {:url url :status (:status value)})

                  :else
                  value))))

(defn- exchange!
  "The response to the `request`, sent by `opts` without following a
  redirect, or a map of the :error."
  [request {:keys [send max-json-bytes] :as opts}]
  (async/then (http/try-send! send request (assoc opts
                                                  :max-bytes max-json-bytes
                                                  :max-redirects 0))
              (fn [{:keys [value error]}]
                (or value {:error (http/failure error)}))))

(defn- page-nodes
  "The Hiccup of the HTML page in the `response`, or nil when it holds
  another kind of document."
  [{:keys [headers body] :as response}]
  (let [type (headers/media-type (headers/header headers "content-type"))]
    (when (and (string? body)
               (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (html/parse body))))

;; IndieAuth 4.1
(defn endpoints
  "The URL of the metadata that the `response` of a profile URL names, as
  a map of :metadata-url, or else the endpoints of its older links, as a
  map of :authorization-endpoint and :token-endpoint, by the :body-links?
  of `opts`. Nil when it names none.

  The Link headers count before the page, and a page counts when it's
  HTML. A relative URL counts from the URL of the response, or from the
  base of the page."
  ([response]
   (endpoints response {}))
  ([response opts]
   (let [nodes     (page-nodes response)
         first-url #(first (links/rel-urls % response nodes opts))]
     (if-let [metadata-url (first-url "indieauth-metadata")]
       {:metadata-url metadata-url}
       ;; the links of earlier versions of IndieAuth
       (when-let [authorization-endpoint (first-url "authorization_endpoint")]
         {:authorization-endpoint authorization-endpoint
          :token-endpoint         (first-url "token_endpoint")})))))

;; IndieAuth 4.1.1
(defn metadata-problem
  "What's wrong with the `metadata` of a server, the map of its JSON, from
  `metadata-url`, or nil."
  [{:keys [issuer authorization_endpoint token_endpoint] :as metadata}
   metadata-url]
  (cond
    (not (map? metadata))
    "The metadata isn't a JSON object"

    (not (issuer? issuer))
    "The issuer isn't an https URL without a query or a fragment"

    (not (issuer-of? issuer metadata-url))
    "The issuer isn't a prefix of the URL of the metadata"

    (not (url/web-url? authorization_endpoint))
    "The authorization endpoint isn't an http or https URL"

    (and (some? token_endpoint) (not (url/web-url? token_endpoint)))
    "The token endpoint isn't an http or https URL"))

(defn- server!
  "The server that the `found` endpoints of the page of `me` name, as
  discover! gives it with the `base` of what it found before, by `opts`."
  [found base {:keys [max-json-bytes] :as opts}]
  (let [{:keys [metadata-url authorization-endpoint]} found]
    (cond
      metadata-url
      (async/then (fetch! metadata-url "application/json" max-json-bytes opts)
                  (fn [{:keys [error body] :as response}]
                    (let [metadata (json/read-object body)
                          problem  (metadata-problem metadata metadata-url)]
                      (cond
                        error
                        response

                        problem
                        (failure ::invalid-metadata problem {:url metadata-url})

                        :else
                        (merge base
                               {:metadata-url           metadata-url
                                :metadata               metadata
                                :issuer                 (:issuer metadata)
                                :authorization-endpoint (:authorization_endpoint metadata)
                                :token-endpoint         (:token_endpoint metadata)})))))

      (url/web-url? authorization-endpoint)
      (merge base found)

      :else
      (failure ::no-server "The page names no IndieAuth server"
               {:url (:me base)}))))

;; IndieAuth 4.1 and 5.1
(defn discover!
  "Fetch the page of the profile URL `url` and the metadata of the server
  that it names, with `opts`, and give the server as a map:

  - :me, the URL in canonical form
  - :urls, the URLs that discovery went through: :me, those that
    redirected, and the last
  - :metadata-url, and :metadata, the server's JSON, unless the page has
    only the older links
  - :issuer, :authorization-endpoint and :token-endpoint

  A failure gives a map of the :error, with its :type and :reason. The
  `opts` are those of default-options and http/fetch!. In ClojureScript,
  it gives a promise."
  ([url]
   (discover! url {}))
  ([url opts]
   (let [{:keys [profile-url-pred max-page-bytes] :as opts} (merge default-options
                                                                   opts)
         me (canonical-url url)]
     (if-not (and me (profile-url-pred me))
       (async/then nil (constantly (failure ::invalid-url
                                            (str "Not a profile URL: " url)
                                            {:url url})))
       (async/then
        (fetch! me "text/html, application/xhtml+xml;q=0.9, */*;q=0.1"
                max-page-bytes opts)
        (fn [{:keys [error redirects] :as response}]
          (if error
            response
            (server! (endpoints response opts)
                     {:me   me
                      :urls (vec (distinct (concat [me]
                                                   (map second redirects)
                                                   [(:url response)])))}
                     opts))))))))

(def ^:no-doc session-kind
  "The kind of a signed state that carries a session."
  ::session)

;; IndieAuth 5.2.1: the state can hold the session
(defn state-session
  "The session that the signed `state` carries, which authorization-request
  gave with the `secret`, or nil when it isn't one, or is older than the
  :session-seconds of `opts`."
  ([secret state]
   (state-session secret state {}))
  ([secret state opts]
   (let [{:keys [session-seconds now-fn]} (merge default-options opts)]
     (some-> (signed/unsign secret session-kind state (now-fn) session-seconds)
             (assoc :state         state
                    :code-verifier (signed/derive-text secret "code_verifier"
                                                       state))))))

(defn- request-problem
  "What's wrong with the options of an authorization request: its
  `client-id`, `redirect-uri` and `scopes`, or nil."
  [client-id redirect-uri scopes]
  (cond
    (not (client-id? client-id))
    "The :client-id isn't a valid client identifier"

    (not (url/web-url? redirect-uri))
    "The :redirect-uri isn't an http or https URL"

    (nil? scopes)
    "The :scope has a scope that isn't valid"

    :else
    (profile-scope-problem scopes)))

;; IndieAuth 5.2
(defn authorization-request
  "The URL at the authorization endpoint of the `discovery` to send the
  user's browser to, and the session to keep until the browser comes
  back, as a map of :url and :session, by `opts`:

  - :client-id, the client identifier
  - :redirect-uri, the URL that the browser comes back to
  - :scope, the scopes to ask for, as a text or a collection. Without one,
    the server only says who the user is.
  - :secret, a text of 32 bytes or more, e.g. a token, to sign the session
    into the state, so that state-session gets it back from the state
  - :now-fn, as default-options has it

  Keep the session where the browser's next request finds it, e.g. in a
  session store or a signed cookie, since it holds the PKCE code verifier
  and the state that ties the answer to this browser. A scope that asks
  for an access token needs a token endpoint, and a server without one
  gives a map of the :error."
  [{:keys [me authorization-endpoint token-endpoint] :as discovery}
   {:keys [client-id redirect-uri scope secret] :as opts}]
  (let [{:keys [now-fn]} (merge default-options opts)
        scopes           (if (string? scope) (scopes scope) (vec (distinct scope)))]
    (when-let [problem (request-problem client-id redirect-uri scopes)]
      (throw (ex-info problem {:client-id    client-id
                               :redirect-uri redirect-uri
                               :scope        scope})))
    (if (and (token-scope? scopes) (not (url/web-url? token-endpoint)))
      (failure ::no-token-endpoint
               "The server has no token endpoint to give an access token"
               {:url authorization-endpoint})
      (let [session  (merge (select-keys discovery [:me :urls :issuer
                                                    :authorization-endpoint
                                                    :token-endpoint])
                            {:client-id    client-id
                             :redirect-uri redirect-uri
                             :scope        (scope-text scopes)})
            state    (if secret
                       (signed/sign secret session-kind session (now-fn))
                       (token))
            verifier (if secret
                       (signed/derive-text secret "code_verifier" state)
                       (code-verifier))]
        {:url     (url/with-query authorization-endpoint
                    [["response_type" "code"]
                     ["client_id" client-id]
                     ["redirect_uri" redirect-uri]
                     ["state" state]
                     ["code_challenge" (code-challenge verifier)]
                     ["code_challenge_method" "S256"]
                     ["scope" (scope-text scopes)]
                     ["me" me]])
         :session (assoc session :state state :code-verifier verifier)}))))

(defn- param
  "The value of the parameter `k` in `params`, a map whose keys are texts
  or keywords, and the first when it has several."
  [params k]
  (let [v (get params k (get params (keyword k)))]
    (if (sequential? v) (first v) v)))

;; IndieAuth 5.2.1; RFC 9207, section 2.4; RFC 6749, section 4.1.2.1
(defn callback-problem
  "What's wrong with the query `params` that the browser came back with,
  for the `session`, as a map of the :type and the :reason, or nil.

  The params are a map by name, with texts or keywords as keys. The state
  must be the session's, and iss must be the issuer of the server, the
  same text, unless the server has the older links alone and so no
  issuer. An answer of the server with an error, e.g. access_denied when
  the user said no, is a problem of the type ::authorization-error, with
  the :code that the server gave."
  [{:keys [state issuer] :as session} params]
  (let [given (param params "state")
        iss   (param params "iss")
        error (param params "error")]
    (cond
      (not (and (string? given)
                (string? state)
                (bytes/same? (bytes/encode given) (bytes/encode state))))
      {:type ::state-mismatch :reason "The state isn't the one that the client sent"}

      (and issuer (not= issuer iss))
      {:type ::issuer-mismatch :reason "The iss isn't the issuer of the server"}

      error
      {:type   ::authorization-error
       :code   error
       :reason (or (param params "error_description")
                   (str "The server answered " error))}

      (empty? (param params "code"))
      {:type ::no-code :reason "The server gave no code"})))

(defn ^:no-doc redeem-at
  "Where the `session` redeems its code: :token at the token endpoint for an
  access token, or else :authorization at the authorization endpoint."
  [{:keys [scope] :as session}]
  (if (token-scope? (scopes scope))
    :token
    :authorization))

;; IndieAuth 5.3.1
(defn redemption-request
  "The request map that redeems the `code` for the `session`: at the token
  endpoint for an access token, when the session asks for one, and else
  at the authorization endpoint for the profile URL alone. The body is a
  hidden text of wary-fetch, since it holds the code and the verifier."
  [{:keys [client-id redirect-uri code-verifier] :as session} code]
  {:method  :post
   :url     (if (= :token (redeem-at session))
              (:token-endpoint session)
              (:authorization-endpoint session))
   :headers {"Content-Type" "application/x-www-form-urlencoded"
             "Accept"       "application/json"}
   :body    (secret/hide (url/query-string [["grant_type" "authorization_code"]
                                            ["code" code]
                                            ["client_id" client-id]
                                            ["redirect_uri" redirect-uri]
                                            ["code_verifier" code-verifier]]))})

;; IndieAuth 5.3.2 and 5.3.3; RFC 6749, section 5.2
(defn redemption
  "The answer in the `response` to a redemption-request, by the
  :profile-url-pred of `opts`: the map of its JSON, with the :me in
  canonical form, or a map of the :error.

  An error of the server is of the type ::redemption-error, with the :code
  that the server gave, e.g. invalid_grant. An answer without a valid
  profile URL as its me is an error too."
  ([response]
   (redemption response {}))
  ([{:keys [status body] :as response} opts]
   (let [{:keys [profile-url-pred]} (merge default-options opts)
         m                          (json/read-object body)
         me                         (when (string? (:me m))
                                      (canonical-url (:me m)))]
     (cond
       (not (and (integer? status) (<= 200 status 299)))
       (failure ::redemption-error
                (or (when (string? (:error_description m)) (:error_description m))
                    (str "The server answered " status))
                (cond-> {:status status}
                  (string? (:error m)) (assoc :code (:error m))))

       (nil? m)
       (failure ::redemption-error "The server's answer isn't a JSON object"
                {:status status})

       (nil? (:me m))
       (failure ::no-me "The server's answer has no me")

       (not (and me (profile-url-pred me)))
       (failure ::invalid-me (str "The me isn't a profile URL: " (:me m)))

       :else
       (assoc m :me me)))))

;; IndieAuth 5.4
(defn confirm!
  "Confirm that the server of the `session` may speak for the profile URL
  `me` that it gave, with `opts`, and give a map of the :me, or of the
  :error. In ClojureScript, it gives a promise.

  It may when `me` is the URL that the user gave, or one that discovery
  went through, and else when the page of `me` names the same
  authorization endpoint."
  [{:keys [urls authorization-endpoint] :as session} me opts]
  (let [seen (set (keep canonical-url (cons (:me session) urls)))]
    (async/then (if (contains? seen me)
                  {:me me}
                  (discover! me opts))
                (fn [{:keys [error] :as found}]
                  (cond
                    (contains? seen me)
                    {:me me}

                    error
                    (failure ::unconfirmed
                             (str "The page of " me " couldn't confirm it: "
                                  (:reason error))
                             {:me me})

                    (= authorization-endpoint (:authorization-endpoint found))
                    {:me me}

                    :else
                    (failure ::unconfirmed (str "The page of " me
                                                " names another server")
                             {:me me}))))))

(defn redeem!
  "Finish signing in when the user's browser comes back with the query
  `params`, for the `session` that authorization-request gave, with
  `opts`, and give what the server answered: the map of its JSON, e.g.
  with :me, :access_token, :scope and :profile, with the :me in canonical
  form. In ClojureScript, it gives a promise.

  It checks the params with callback-problem, redeems the code with
  redemption-request, and confirms the :me with confirm!. A failure at
  any of them gives a map of the :error, with its :type and its :reason.
  The profile, if any, is what the user chose to share, so it never says
  who the user is: the :me does. The `opts` are those of default-options."
  ([session params]
   (redeem! session params {}))
  ([session params opts]
   (let [opts (merge default-options opts)]
     (if-let [problem (callback-problem session params)]
       (async/then nil (constantly {:error problem}))
       (async/then
        (exchange! (redemption-request session (param params "code")) opts)
        (fn [{:keys [error] :as response}]
          (let [answer (if error response (redemption response opts))]
            (if (:error answer)
              answer
              (async/then (confirm! session (:me answer) opts)
                          (fn [{:keys [error] :as confirmed}]
                            (if error confirmed answer)))))))))))

;; IndieAuth 4.2.1
(defn client-metadata
  "The client metadata document to serve at the client identifier, as a
  map of its JSON, by `opts`:

  - :client-id, the client identifier
  - :client-name, the name of the client to show the user
  - :client-uri, a page about the client, the client identifier by default
  - :logo-uri, the URL of its logo
  - :redirect-uris, the URLs that the browser may come back to, which a
    redirect URL on another host than the client identifier's must be
    among

  The page about the client is a prefix of the client identifier, as the
  spec says."
  [{:keys [client-id client-name client-uri logo-uri redirect-uris]
    :or   {client-uri client-id}
    :as   opts}]
  (when-not (client-id? client-id)
    (throw (ex-info "The :client-id isn't a valid client identifier"
                    {:client-id client-id})))
  (when-not (and (url/web-url? client-uri)
                 (str/starts-with? client-id client-uri))
    (throw (ex-info "The :client-uri is a prefix of the :client-id"
                    {:client-id client-id :client-uri client-uri})))
  (cond-> {:client_id  client-id
           :client_uri client-uri}
    client-name         (assoc :client_name client-name)
    logo-uri            (assoc :logo_uri logo-uri)
    (seq redirect-uris) (assoc :redirect_uris (vec redirect-uris))))

(defn client-metadata-handler
  "A Ring handler that serves the client metadata document of the `opts`
  of client-metadata as JSON, which a page in any browser can read."
  [opts]
  (let [body (json/write-json (client-metadata opts))]
    (ring/handler
     (fn [{:keys [request-method] :as request}]
       (case request-method
         (:get :head) (ring/with-cors (ring/response 200 "application/json" body))
         :options     (ring/with-cors (ring/text-response 204 ""))
         (ring/not-allowed ["GET" "HEAD" "OPTIONS"]))))))
