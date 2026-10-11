(ns dk.simongray.indieauth
  "IndieAuth for clients: the identifiers of users, clients and servers,
  the discovery of a user's server, and signing in with it.

  The code follows the IndieAuth Living Standard of 11 July 2024 at
  https://indieauth.spec.indieweb.org/ and cites its sections. The server
  is in dk.simongray.indieauth.server, the checks of a resource server in
  dk.simongray.indieauth.resource, the signed maps that carry a value
  through a browser in dk.simongray.indieauth.signed, and the signed state
  of a sign-in, which other protocols can use too, in
  dk.simongray.indieauth.state. The other namespaces are internal and
  named for what they hold, e.g. identifier for the parts of URLs and
  grant for the codes and tokens of a server."
  (:require [clojure.string :as str]
            [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.fetch :as fetch]
            [dk.simongray.indieauth.identifier :as identifier]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.state :as state]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.bytes :as bytes]
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.url :as url]))

;;; identifiers

;; IndieAuth 3.2
(defn profile-url?
  "Whether `s` is a valid profile URL of a user: an http or https URL with
  a domain name, without a port, a fragment, a user name or a password,
  or a . or .. segment in its path.

      (profile-url? \"https://example.com/users?id=100\") ;; => true
      (profile-url? \"https://example.com:8443/\")        ;; => false"
  [s]
  (let [{:keys [host port]} (identifier/parts s)]
    (boolean (and host (nil? port) (identifier/domain-name? host)))))

;; IndieAuth 3.3
(defn client-id?
  "Whether `s` is a valid client identifier: an http or https URL with a
  domain name, 127.0.0.1 or [::1], without a fragment, a user name or a
  password, or a . or .. segment in its path. Unlike a profile URL, it
  can have a port."
  [s]
  (let [{:keys [host port]} (identifier/parts s)]
    (boolean (and host
                  (or (nil? port) (identifier/port? port))
                  (or (identifier/domain-name? host)
                      (contains? identifier/loopback-hosts host))))))

;; IndieAuth 3.1; RFC 9207, section 2
(defn issuer?
  "Whether `s` is a valid issuer identifier of a server: an https URL with
  a host, and without a query or a fragment."
  [s]
  (let [{:keys [scheme host query fragment]} (url/parts s)]
    (boolean (and (string? s)
                  (= "https" scheme)
                  (seq host)
                  (nil? query)
                  (nil? fragment)
                  (not (re-find identifier/unsafe-characters s))))))

;; RFC 8414, section 3.1
(defn well-known-url
  "The URL of the metadata of the server whose issuer identifier is
  `issuer`, at the well-known location of RFC 8414.

      (well-known-url \"https://example.com/indieauth/\")
      ;; => \"https://example.com/.well-known/oauth-authorization-server/indieauth\""
  [issuer]
  (let [{:keys [scheme authority path]} (url/parts issuer)]
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
  (let [{:keys [scheme userinfo host port path query fragment]}
        (url/parts (identifier/with-scheme (str/trim (str s))))]
    (when (and (#{"http" "https"} scheme) (seq host))
      (str scheme "://"
           (some-> userinfo (str "@"))
           (str/lower-case host)
           (when (and port (not= port (identifier/default-ports scheme)))
             (str ":" port))
           (if (empty? path) "/" path)
           (some->> query (str "?"))
           (some->> fragment (str "#"))))))

;;; secrets, PKCE and scopes

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
  (digest/text verifier))

;; RFC 6749, section 3.3
(defn scopes
  "The scopes of `x`, a text of scopes separated by spaces, or a collection
  of them, as a vector without repeats. It's empty when there are none, and
  nil when a scope has a character that a scope can't have."
  [x]
  (let [xs (re-seq #"[^ ]+" (if (string? x) x (str/join " " x)))]
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

;;; discovery

(def default-options
  "The default of each option of a client that has one, which follows
  IndieAuth:

  - :profile-url-pred, profile-url?, the URLs that a user can sign in as
  - :body-links?, false: only the head of a page names its server, since
    anyone who writes in its body could name another
  - :session-seconds, how long a user has to sign in at the server
  - :max-redirects, how many redirects discovery follows
  - :timeout-seconds, :max-page-bytes and :max-json-bytes, the limits of
    each request
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
   :now-fn           instant/now})

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
   (let [all       (fetch/links response (fetch/page-html response) opts)
         first-url #(first (fetch/hrefs % all))]
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

(defn- metadata-server
  "The server that the `metadata` from `metadata-url` describes, over the
  `discovery` that found it."
  [discovery metadata metadata-url]
  (let [{:keys [issuer authorization_endpoint token_endpoint
                revocation_endpoint userinfo_endpoint]} metadata]
    (cond-> (assoc discovery
                   :metadata-url           metadata-url
                   :metadata               metadata
                   :issuer                 issuer
                   :authorization-endpoint authorization_endpoint
                   :token-endpoint         token_endpoint)
      (url/web-url? revocation_endpoint) (assoc :revocation-endpoint revocation_endpoint)
      (url/web-url? userinfo_endpoint)   (assoc :userinfo-endpoint userinfo_endpoint))))

(defn- server!
  "The server of the `found` endpoints, over the `discovery` that found
  them, which fetches its metadata by `opts`."
  [{:keys [metadata-url authorization-endpoint] :as found} discovery
   {:keys [max-json-bytes] :as opts}]
  (cond
    metadata-url
    (async/then (fetch/get! metadata-url "application/json" max-json-bytes opts)
                (fn [{:keys [error body] :as response}]
                  (if error
                    response
                    (let [metadata (fetch/json-object body)]
                      (if-let [problem (metadata-problem metadata metadata-url)]
                        (fetch/failure ::invalid-metadata problem {:url metadata-url})
                        (metadata-server discovery metadata metadata-url))))))

    (url/web-url? authorization-endpoint)
    (merge discovery found)

    :else
    (fetch/failure ::no-server "The page names no IndieAuth server" {:url (:me discovery)})))

;; IndieAuth 4.1 and 5.1
(defn discover!
  "Fetch the page of the profile URL `url` and the metadata of the server
  that it names, with `opts`, and give the server as a map:

  - :me, the URL in canonical form
  - :urls, the URLs that discovery went through, from :me to the last
    redirect
  - :metadata-url and :metadata, unless the page has only older links
  - :issuer and the endpoints that the server has

  A failure gives a map of the :error, with its :type and :reason. The
  `opts` are those of default-options and http/fetch!. In ClojureScript,
  it gives a promise."
  ([url]
   (discover! url {}))
  ([url opts]
   (let [{:keys [profile-url-pred max-page-bytes] :as opts} (merge default-options opts)
         me                                                (canonical-url url)]
     (if-not (and me (profile-url-pred me))
       (async/then (fetch/failure ::invalid-url (str "Not a profile URL: " url) {:url url})
                   identity)
       (async/then
        (fetch/get! me "text/html, application/xhtml+xml;q=0.9, */*;q=0.1" max-page-bytes opts)
        (fn [{:keys [error redirects] :as response}]
          (if error
            response
            (server! (endpoints response opts)
                     {:me   me
                      :urls (vec (distinct (concat [me]
                                                   (map second redirects)
                                                   [(:url response)])))}
                     opts))))))))

;;; signing in

(defn- request-problem
  "What's wrong with the options of an authorization request: its
  `client-id`, `redirect-uri` and `scopes`, or nil."
  [client-id redirect-uri scopes]
  (cond
    (not (client-id? client-id))       "The :client-id isn't a valid client identifier"
    (not (url/web-url? redirect-uri))  "The :redirect-uri isn't an http or https URL"
    (nil? scopes)                      "The :scope has a scope that isn't valid"
    :else                              (profile-scope-problem scopes)))

;; IndieAuth 5.2
(defn authorization-request
  "The URL at the authorization endpoint of the `discovery` to send the
  user's browser to, and the session to keep until the browser comes
  back, as a map of :url and :session, by `opts`:

  - :client-id, the client identifier
  - :redirect-uri, the URL that the browser comes back to
  - :scope, the scopes to ask for, as a text or a collection. Without one,
    the answer has the user's profile URL alone.
  - :secret, a text of 32 bytes or more, e.g. a token, that signs the
    session into the state for state-session
  - :data, any EDN that the session carries for you
  - :now-fn, as default-options has it

  Keep the session for the browser's return, e.g. in a session store, or
  with a :secret, only its :nonce in a cookie. A scope that asks for an
  access token needs a token endpoint, and a server without one gives a
  map of the :error."
  [{:keys [me authorization-endpoint token-endpoint] :as discovery}
   {:keys [client-id redirect-uri scope secret data] :as opts}]
  (let [{:keys [now-fn]} (merge default-options opts)
        asked            (scopes scope)]
    (when-let [problem (request-problem client-id redirect-uri asked)]
      (throw (ex-info problem {:client-id    client-id
                               :redirect-uri redirect-uri
                               :scope        scope})))
    (if (and (token-scope? asked) (not (url/web-url? token-endpoint)))
      (fetch/failure ::no-token-endpoint
                     "The server has no token endpoint to give an access token"
                     {:url authorization-endpoint})
      (let [session (cond-> (merge (select-keys discovery [:me :urls :issuer
                                                           :authorization-endpoint
                                                           :token-endpoint
                                                           :revocation-endpoint
                                                           :userinfo-endpoint])
                                   {:client-id    client-id
                                    :redirect-uri redirect-uri
                                    :scope        (scope-text asked)})
                      (some? data) (assoc :data data))
            {:keys [state code-verifier] :as fresh} (state/fresh secret ::session session (now-fn))]
        {:url     (url/with-query authorization-endpoint
                    [["response_type" "code"]
                     ["client_id" client-id]
                     ["redirect_uri" redirect-uri]
                     ["state" state]
                     ["code_challenge" (code-challenge code-verifier)]
                     ["code_challenge_method" "S256"]
                     ["scope" (scope-text asked)]
                     ["me" me]])
         :session (merge session fresh)}))))

;; IndieAuth 5.2.1: the state can hold the session; RFC 9700, section
;; 4.7.1: a state that is bound to the browser
(defn state-session
  "The session that the signed `state` carries, which authorization-request
  gave with the `secret`, if the `nonce` is the session's, or nil. It's nil
  too when the state is older than the :session-seconds of `opts`.

  The nonce comes from the browser that came back, e.g. from a cookie,
  so that only the browser that started the sign-in can finish it."
  ([secret state nonce]
   (state-session secret state nonce {}))
  ([secret state nonce opts]
   (let [{:keys [session-seconds now-fn]} (merge default-options opts)]
     (state/session secret ::session state nonce (now-fn) session-seconds))))

;; IndieAuth 5.2.1; RFC 9207, section 2.4; RFC 6749, section 4.1.2.1
(defn callback-problem
  "What's wrong with the query `params` that the browser came back with,
  for the `session`, as a map of the :type and the :reason, or nil.

  The params are a map with texts or keywords as keys. An error from the
  server, e.g. access_denied when the user said no, is a problem of the
  type ::authorization-error, with the server's :code."
  [{:keys [state issuer] :as session} params]
  (let [error (ring/param params "error")]
    (cond
      (not (bytes/same-text? (ring/param params "state") state))
      {:type ::state-mismatch :reason "The state isn't the one that the client sent"}

      (and issuer (not= issuer (ring/param params "iss")))
      {:type ::issuer-mismatch :reason "The iss isn't the issuer of the server"}

      error
      {:type   ::authorization-error
       :code   error
       :reason (or (ring/param params "error_description")
                   (str "The server answered " error))}

      (empty? (ring/param params "code"))
      {:type ::no-code :reason "The server gave no code"})))

;; IndieAuth 5.3.1
(defn redemption-request
  "The request map that redeems the `code` for the `session`: at the token
  endpoint for an access token, when the session asks for one, and else
  at the authorization endpoint for the profile URL alone. The body is a
  hidden text of wary-fetch, since it holds the code and the verifier."
  [{:keys [scope client-id redirect-uri code-verifier] :as session} code]
  (fetch/form-request (if (token-scope? (scopes scope))
                        (:token-endpoint session)
                        (:authorization-endpoint session))
                      [["grant_type" "authorization_code"]
                       ["code" code]
                       ["client_id" client-id]
                       ["redirect_uri" redirect-uri]
                       ["code_verifier" code-verifier]]))

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
         m                          (fetch/json-object body)
         me                         (when (string? (:me m))
                                      (canonical-url (:me m)))]
     (cond
       (not (ring/success? status))
       (fetch/server-error ::redemption-error status m)

       (nil? m)
       (fetch/failure ::redemption-error "The server's answer isn't a JSON object"
                      {:status status})

       (nil? (:me m))
       (fetch/failure ::no-me "The server's answer has no me")

       (not (and me (profile-url-pred me)))
       (fetch/failure ::invalid-me (str "The me isn't a profile URL: " (:me m)))

       :else
       (assoc m :me me)))))

;; IndieAuth 5.4
(defn confirm!
  "Confirm that the profile URL `me`, which the server of the `session`
  gave, names that server, with `opts`, and give a map of the :me, or of
  the :error. In ClojureScript, it gives a promise.

  It does when `me` is the URL that the user gave, or one that discovery
  went through, and else when the page of `me` names the same
  authorization endpoint."
  [{:keys [urls authorization-endpoint] :as session} me opts]
  (if (contains? (set (keep canonical-url (cons (:me session) urls))) me)
    (async/then {:me me} identity)
    (async/then (discover! me opts)
                (fn [{:keys [error] :as found}]
                  (cond
                    error
                    (fetch/failure ::unconfirmed
                                   (str "The page of " me " couldn't confirm it: " (:reason error))
                                   {:me me})

                    (= authorization-endpoint (:authorization-endpoint found))
                    {:me me}

                    :else
                    (fetch/failure ::unconfirmed (str "The page of " me " names another server")
                                   {:me me}))))))

(defn redeem!
  "Finish signing in when the user's browser comes back with the query
  `params`, for the `session` that authorization-request gave, with
  `opts`, and give what the server answered: the map of its JSON, e.g.
  with :me, :access_token, :scope and :profile, with the :me in canonical
  form. In ClojureScript, it gives a promise.

  It checks the params with callback-problem, redeems the code with
  redemption-request, and confirms the :me with confirm!. A failure gives
  a map of the :error, with its :type and :reason. Only the :me says who
  the user is, never the :profile. The `opts` are those of
  default-options."
  ([session params]
   (redeem! session params {}))
  ([session params opts]
   (let [opts (merge default-options opts)]
     (if-let [problem (callback-problem session params)]
       (async/then {:error problem} identity)
       (async/then
        (fetch/exchange! (redemption-request session (ring/param params "code")) opts)
        (fn [{:keys [error] :as response}]
          (let [answer (if error response (redemption response opts))]
            (if (:error answer)
              answer
              (async/then (confirm! session (:me answer) opts)
                          #(if (:error %) % answer))))))))))

;;; after signing in

;; IndieAuth 5.5.1; RFC 6749, section 6
(defn refresh-request
  "The request map that exchanges the `refresh-token` for a new access
  token at the token endpoint of the `session`, for the :scope of `opts`,
  the scopes of the session by default.

  A scope that the session didn't ask for throws, since a refresh asks for
  the same scopes or fewer."
  ([session refresh-token]
   (refresh-request session refresh-token {}))
  ([{:keys [token-endpoint client-id] :as session} refresh-token {:keys [scope] :as opts}]
   (let [asked (scopes scope)]
     (when-not (and asked (every? (set (scopes (:scope session))) asked))
       (throw (ex-info "A refresh asks for the scopes of the session, or fewer"
                       {:scope scope :granted (:scope session)})))
     (fetch/form-request token-endpoint [["grant_type" "refresh_token"]
                                         ["refresh_token" refresh-token]
                                         ["client_id" client-id]
                                         ["scope" (scope-text asked)]]))))

(defn refresh!
  "Exchange the `refresh-token` for a new access token at the token
  endpoint of the `session`, with `opts`, and give the answer as redeem!
  does. In ClojureScript, it gives a promise.

  The answer has a new :refresh_token when the server gives one, which
  replaces the old one, as section 5.5.1 says. The `opts` are those of
  refresh-request and default-options."
  ([session refresh-token]
   (refresh! session refresh-token {}))
  ([session refresh-token opts]
   (let [opts (merge default-options opts)]
     (async/then (fetch/exchange! (refresh-request session refresh-token opts) opts)
                 #(if (:error %) % (redemption % opts))))))

;; IndieAuth 7; RFC 7009, section 2.1
(defn revocation-request
  "The request map that revokes the `token`, an access token or a refresh
  token, at the revocation endpoint of the `session`. Without one, it goes
  to the token endpoint with action=revoke, as earlier versions of
  IndieAuth had it."
  [{:keys [revocation-endpoint token-endpoint] :as session} token]
  (fetch/form-request (or revocation-endpoint token-endpoint)
                      (cond-> [["token" token]]
                        (nil? revocation-endpoint) (conj ["action" "revoke"]))))

(defn revoke!
  "Revoke the `token`, an access token or a refresh token, at the server of
  the `session`, with `opts`, e.g. when the user signs out, and give a map
  of the :status, or of the :error. In ClojureScript, it gives a promise.

  A server revokes a refresh token with the access tokens of its grant.
  The `opts` are those of default-options."
  ([session token]
   (revoke! session token {}))
  ([{:keys [revocation-endpoint token-endpoint] :as session} token opts]
   (if-not (or revocation-endpoint token-endpoint)
     (async/then (fetch/failure ::no-revocation-endpoint
                                "The server has no endpoint to revoke a token")
                 identity)
     (async/then (fetch/exchange! (revocation-request session token)
                                  (merge default-options opts))
                 (fn [{:keys [error status] :as response}]
                   (cond
                     error                  response
                     (ring/success? status) {:status status}
                     :else                  (fetch/server-error ::revocation-error status nil)))))))

;; IndieAuth 9; RFC 6750, section 2.1
(defn userinfo!
  "Fetch the user's profile information from the userinfo endpoint of the
  `session` with the `access-token`, which needs the profile scope, with
  `opts`, and give the map of its JSON, or of the :error. In ClojureScript,
  it gives a promise.

  Like the :profile of redeem!, it never says who the user is. The `opts`
  are those of default-options."
  ([session access-token]
   (userinfo! session access-token {}))
  ([{:keys [userinfo-endpoint] :as session} access-token opts]
   (if-not (url/web-url? userinfo-endpoint)
     (async/then (fetch/failure ::no-userinfo-endpoint "The server has no userinfo endpoint")
                 identity)
     (async/then
      (fetch/exchange! {:url     userinfo-endpoint
                        :headers {"Accept"        "application/json"
                                  "Authorization" (http/authorization {:token access-token})}}
                       (merge default-options opts))
      (fn [{:keys [error status body] :as response}]
        (let [m (fetch/json-object body)]
          (cond
            error                        response
            (not (ring/success? status)) (fetch/server-error ::userinfo-error status m)
            (nil? m)                     (fetch/failure ::userinfo-error
                                                        "The server's answer isn't a JSON object"
                                                        {:status status})
            :else                        m)))))))

;;; client metadata

;; IndieAuth 4.2.1
(defn client-metadata
  "The client metadata document to serve at the client identifier, as a
  map of its JSON, by `opts`:

  - :client-id, the client identifier
  - :client-name, the name of the client to show the user
  - :client-uri, a page about the client, which is a prefix of the client
    identifier, and the client identifier by default
  - :logo-uri, the URL of its logo
  - :redirect-uris, the redirect URLs, which must list any on another
    host than the client identifier's"
  [{:keys [client-id client-name client-uri logo-uri redirect-uris] :as opts}]
  (let [page (or client-uri client-id)]
    (when-not (client-id? client-id)
      (throw (ex-info "The :client-id isn't a valid client identifier"
                      {:client-id client-id})))
    (when-not (and (url/web-url? page) (str/starts-with? client-id page))
      (throw (ex-info "The :client-uri is a prefix of the :client-id"
                      {:client-id client-id :client-uri page})))
    (cond-> {:client_id  client-id
             :client_uri page}
      client-name         (assoc :client_name client-name)
      logo-uri            (assoc :logo_uri logo-uri)
      (seq redirect-uris) (assoc :redirect_uris (vec redirect-uris)))))

(defn client-metadata-handler
  "A Ring handler that serves the client metadata document of the `opts`
  of client-metadata as JSON, which a page in any browser can read."
  [opts]
  (let [document (constantly (ring/with-cors
                              (ring/response 200 "application/json"
                                             (json/write-json (client-metadata opts)))))]
    (ring/handler {:get     document
                   :head    document
                   :options (constantly ring/preflight)})))
