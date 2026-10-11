(ns dk.simongray.indieauth.server
  "An IndieAuth server: the authorization, token, revocation,
  introspection and userinfo endpoints and the metadata document.

  Signing the user in and asking for consent are up to you: the
  :authorize function of handler gets the checked request, and approve!
  gives the client its code when the user says yes. Codes and tokens go in
  stores of yours, or in memory-store, as hashes. In ClojureScript, the
  handlers answer with promises, and take a body that has been read.

  Its internals are in info, authorization, grant and endpoint."
  (:require [clojure.string :as str]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.authorization :as authorization]
            [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.endpoint :as endpoint]
            [dk.simongray.indieauth.fetch :as fetch]
            [dk.simongray.indieauth.grant :as grant]
            [dk.simongray.indieauth.identifier :as identifier]
            [dk.simongray.indieauth.info :as info]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.url :as url]))

(def default-options
  "The default of each option of a server that has one, which follows
  IndieAuth:

  - :scopes-supported, the scopes that the metadata lists. Add those of
    your resource servers, e.g. create for Micropub.
  - :code-seconds, :token-seconds and :refresh-seconds, how long a code,
    an access token and an unused refresh token last. A nil
    :token-seconds gives tokens that never expire, and a nil
    :refresh-seconds no refresh tokens.
  - :request-seconds, how long a user has to sign in and say yes
  - :legacy-revocation?, true: the token endpoint revokes a token with
    action=revoke, as earlier versions of IndieAuth had it
  - :legacy-verification?, false: the token endpoint verifies a token
    with a GET, as the W3C Note of 2018 had it. It tells anyone who has a
    token whose it is, so turn it on only for a resource server that
    needs it.
  - :client-info?, true: the client identifier is fetched for the
    client's name, logo and redirect URLs
  - :client-id-pred and :profile-url-pred, the identifiers that the
    server takes, indieauth/client-id? and indieauth/profile-url?
  - :cors?, true: a page in any browser can read the metadata and redeem
    a code
  - :send, http/send-public!, which never fetches a client identifier on
    the server's own network (section 4.2)
  - :timeout-seconds, :max-page-bytes, :max-json-bytes and
    :max-form-bytes, the limits of the requests to and from a client
  - :now-fn, a function that gives the instant now"
  {:scopes-supported     ["profile" "email"]
   :code-seconds         60
   :token-seconds        86400
   :refresh-seconds      2592000
   :legacy-revocation?   true
   :legacy-verification? false
   :request-seconds      1800
   :client-info?         true
   :client-id-pred       indieauth/client-id?
   :profile-url-pred     indieauth/profile-url?
   :cors?                true
   :timeout-seconds      10
   :max-page-bytes       (* 2 1024 1024)
   :max-json-bytes       (* 256 1024)
   :max-form-bytes       (* 64 1024)
   :send                 http/send-public!
   :now-fn               instant/now})

(defn- options
  "The `opts` of a server over default-options. They must name the
  server's :issuer, its :authorization-endpoint and its :secret."
  [{:keys [issuer authorization-endpoint secret] :as opts}]
  (when-not (and (indieauth/issuer? issuer)
                 (url/web-url? authorization-endpoint)
                 secret)
    (throw (ex-info (str "A server needs its :issuer, an https URL without a"
                         " query, its :authorization-endpoint and a :secret")
                    {:issuer                 issuer
                     :authorization-endpoint authorization-endpoint})))
  (merge default-options opts))

;;; stores

(defn memory-store
  "A store in the atom `a`, or in a new one, which drops each value once
  the instant that `now-fn` gives passes its :expires.

  A store is a map of functions, which can give promises in ClojureScript:

  - :put!, of a key and a value, which keeps the value
  - :get, of a key, which gives its value, or nil
  - :take!, of a key, which gives its value and removes it in one step,
    so that two calls never both get it
  - :delete!, of a key, which removes its value

  The store of codes needs :put! and :take!, and the store of tokens all
  four. A key is the hash of a code or a token, and a value a map whose
  :expires, an instant, says when a store can drop it."
  ([]
   (memory-store (atom {})))
  ([a]
   (memory-store a instant/now))
  ([a now-fn]
   (let [live (fn [m]
                (let [at (now-fn)]
                  (reduce-kv #(if (instant/expired? %3 at) (dissoc %1 %2) %1) m m)))]
     {:put!    (fn [k v]
                 (swap! a #(assoc (live %) k v))
                 nil)
      :get     (fn [k]
                 (get @a k))
      :take!   (fn [k]
                 (get (first (swap-vals! a dissoc k)) k))
      :delete! (fn [k]
                 (swap! a dissoc k)
                 nil)})))

;;; client information

;; IndieAuth 4.2
(defn client-info
  "The client information in the `response` of a GET of the client
  identifier `client-id`, from a client metadata document in JSON or else
  the h-app and the redirect_uri links of an HTML page, as a map:

  - :client-id
  - :client-name, :client-uri and :logo-uri, when it names them
  - :redirect-uris, the redirect URLs that the client lists

  A document that names another client gives the :client-id alone."
  [client-id {:keys [headers body] :as response}]
  (let [type (headers/media-type (headers/header headers "content-type"))
        m    (when (or (nil? type) (re-find #"^application/(.+\+)?json$" type))
               (fetch/json-object body))]
    (cond
      m
      (or (info/document-info client-id m) (info/unknown-client client-id))

      (and (string? body) (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (info/app-info client-id response)

      :else
      (info/unknown-client client-id))))

(defn client-info!
  "Fetch the client identifier `client-id` with `opts`, and give its
  client information as client-info does, or the :client-id alone with
  the :error when it can't be read. A client identifier on a loopback host
  isn't fetched, as section 4.2 says. In ClojureScript, it gives a
  promise."
  ([client-id]
   (client-info! client-id {}))
  ([client-id opts]
   (let [{:keys [max-page-bytes] :as opts} (merge default-options opts)]
     (if (identifier/loopback? client-id)
       (async/then (info/unknown-client client-id) identity)
       (async/then (fetch/get! client-id "application/json, text/html;q=0.9" max-page-bytes opts)
                   (fn [{:keys [error] :as response}]
                     (if error
                       (assoc (info/unknown-client client-id) :error error)
                       (client-info client-id response))))))))

;;; the authorization request

;; IndieAuth 5.2 and 10.1
(defn registered?
  "Whether the client of the client information `info` may have its
  browser sent to `redirect-uri`: one on the scheme, host and port of the
  client identifier, or one that the client lists, the same text."
  [{:keys [client-id redirect-uris] :as info} redirect-uri]
  (boolean (or (and (url/web-url? redirect-uri)
                    (url/same-origin? client-id redirect-uri))
               (some #{redirect-uri} redirect-uris))))

(defn- authorization-request
  "The authorization request of the single-valued `fields`, from the
  client of the client information `info`, as a map of the :request or the
  :error, by `opts`."
  [fields info opts]
  (let [{:strs [redirect_uri state code_challenge scope me]} fields]
    (if-not (registered? info redirect_uri)
      {:error {:code   "invalid_request"
               :reason "redirect_uri isn't one that the client lists"}}
      (or (authorization/request-error fields opts)
          {:request (cond-> {:client-id      (:client-id info)
                             :redirect-uri   redirect_uri
                             :state          state
                             :code-challenge code_challenge
                             :scopes         (indieauth/scopes scope)
                             :client         (dissoc info :redirect-uris)}
                      (indieauth/canonical-url me) (assoc :me (indieauth/canonical-url me)))}))))

;; IndieAuth 5.2, 4.2 and 10.1; RFC 6749, section 4.1.2.1
(defn authorization-request!
  "Check the authorization request of a client with the query `fields`, a
  map by name or pairs of a name and a value, by the `opts` of handler,
  and give the :request, or the :error. In ClojureScript, it gives a
  promise.

  The request is a map:

  - :client-id, :redirect-uri, :state and :code-challenge
  - :scopes, a vector of the scopes that the client asks for
  - :me, the profile URL that the client gave as an unchecked hint
  - :client, the client information of client-info!, to show the user

  An error has the :code of OAuth 2.0 and the :reason, and the :redirect
  that sends the browser back to the client, when the client is known.
  Without it, tell the user the reason."
  [fields opts]
  (let [{:keys [client-info?] :as opts} (options opts)
        fields       (ring/single-values (if (map? fields) (ring/param-fields fields) fields))
        client-id    (indieauth/canonical-url (get fields "client_id"))
        redirect-uri (get fields "redirect_uri")]
    (if-let [problem (authorization/client-problem fields opts)]
      (async/then {:error {:code "invalid_request" :reason problem}} identity)
      (async/then (if (or client-info? (not (url/same-origin? client-id redirect-uri)))
                    (client-info! client-id opts)
                    (info/unknown-client client-id))
                  #(authorization-request (assoc fields "client_id" client-id) % opts)))))

;;; consent and codes

(defn request-token
  "The authorization `request` as a URL-safe text, signed with the :secret
  of `opts`, to carry it through the pages that sign the user in, e.g. in
  a query parameter or a form."
  [request opts]
  (let [{:keys [secret now-fn]} (options opts)]
    (signed/sign secret ::request request (now-fn))))

(defn token-request
  "The authorization request that the `token` of request-token or consent
  carries, if the :secret of `opts` signed it less than :request-seconds
  ago, or nil."
  [token opts]
  (let [{:keys [secret now-fn request-seconds]} (options opts)
        unsign #(signed/unsign secret % token (now-fn) request-seconds)]
    (or (unsign ::request)
        (some-> (unsign ::consent) (dissoc :me)))))

;; IndieAuth 5.2 and 10.1
(defn consent
  "The data for the page that asks the user `me`, who is signed in, to
  consent to the authorization `request`, by `opts`: the request with the
  :me of the user in place of the client's hint, and the :token to post
  back with the answer.

  Show the :client and the :scopes, and let the user grant fewer. The
  token is signed for `me` alone, so it also guards the page's form
  against cross-site requests."
  [request me opts]
  (let [{:keys [secret now-fn profile-url-pred]} (options opts)
        me (indieauth/canonical-url me)
        m  (assoc request :me me)]
    (when-not (and me (profile-url-pred me))
      (throw (ex-info "The user isn't a profile URL" {:me me})))
    (assoc m :token (signed/sign secret ::consent m (now-fn)))))

;; RFC 6749, section 4.1.2.1; RFC 9207, section 2
(defn denial
  "The URL that sends the browser back to the client of the authorization
  `request` when the user says no, with the error access_denied, the state
  and the :issuer of `opts`."
  [{:keys [redirect-uri state] :as request} {:keys [issuer] :as opts}]
  (authorization/error-redirect redirect-uri state issuer "access_denied"
                                "The user didn't consent"))

;; IndieAuth 5.2.1
(defn approve!
  "Give the client of the consent `token` a code for the `grant` of the
  user who said yes, by `opts`, and give the URL to send the browser back
  to, as a map of the :redirect, or of the :error. In ClojureScript, it
  gives a promise.

  The grant is a map:

  - :me, the profile URL of the signed-in user, who must be the one that
    consent gave the token to
  - :scopes, the scopes that the user grants, among those that the client
    asked for, all of them when nil
  - :profile, the user's :name, :url, :photo and :email, which the client
    gets with the profile scope, the email with the email scope too

  The code lasts :code-seconds and works once."
  [token {:keys [me scopes profile] :as grant} opts]
  (let [{:keys [secret now-fn request-seconds code-seconds codes issuer profile-url-pred]
         :as   opts} (options opts)
        at      (now-fn)
        request (signed/unsign secret ::consent token at request-seconds)
        me      (indieauth/canonical-url me)]
    (cond
      (nil? request)
      (async/then {:error {:code   "invalid_request"
                           :reason "The consent is too old, or not this server's"}}
                  identity)

      (not (and me (= me (:me request)) (profile-url-pred me)))
      (async/then {:error {:code   "access_denied"
                           :reason "The consent was given to another user"}}
                  identity)

      :else
      (let [code    (indieauth/token)
            granted (grant/granted-scopes request scopes)
            shared  (grant/granted-profile profile granted)]
        (async/then ((:put! codes) (digest/text code)
                                   (cond-> {:client-id      (:client-id request)
                                            :redirect-uri   (:redirect-uri request)
                                            :code-challenge (:code-challenge request)
                                            :me             me
                                            :scopes         granted
                                            :expires        (instant/later at code-seconds)}
                                     shared (assoc :profile shared)))
                    (fn [_]
                      {:redirect (url/with-query (:redirect-uri request)
                                   [["code" code]
                                    ["state" (:state request)]
                                    ["iss" issuer]])}))))))

;;; the endpoints

(def page-headers
  "The headers of the pages of the authorization endpoint, which no other
  site can frame (RFC 9700, section 4.16), and which tell no other site
  their URL. Add them to your sign-in and consent pages too."
  {"X-Frame-Options"         "DENY"
   "Content-Security-Policy" "frame-ancestors 'none'"
   "Referrer-Policy"         "no-referrer"})

(defn- authorization-page
  "The answer to the GET `ring-request` of a client's authorization
  request, by the :authorize and :error-page of `opts`, with page-headers
  unless it has its own."
  [ring-request {:keys [authorize error-page] :as opts}]
  (async/then
   (authorization-request! (ring/query-fields ring-request) opts)
   (fn [{:keys [request error]}]
     (async/then (cond
                   (:redirect error) {:status 302 :headers {"Location" (:redirect error)} :body ""}
                   (and error error-page) (error-page ring-request error)
                   error             (ring/text-response 400 (str "The authorization request failed: "
                                                                  (:reason error)))
                   :else             (authorize ring-request request))
                 (fn [response]
                   (update response :headers #(merge page-headers %)))))))

;; TODO: email magic links to a rel=me mailto: address, as a way to sign in
;; for :authorize, perhaps in relmeauth-clj, with a limit on mail to each
;; address
(defn handler
  "A Ring handler for the authorization endpoint, by `opts`.

  A GET is a client's authorization request, which authorization-request!
  checks. The handler answers a good one with the :authorize of `opts`, a
  function of the Ring request and the checked request, e.g. a sign-in or
  consent page. For a bad one, it sends the browser back to the client
  with the error, or else answers with the :error-page of `opts`, a
  function of the Ring request and the :error. A POST redeems a code for
  the profile URL alone.

  The `opts` are those of default-options, and these:

  - :issuer, an https URL that is a prefix of the URL of the metadata
  - :authorization-endpoint and :token-endpoint, and the
    :revocation-endpoint, :introspection-endpoint and :userinfo-endpoint
    that you serve
  - :secret, a text of 32 bytes or more, e.g. a token, that signs the
    requests and consents
  - :codes and :tokens, the stores of codes and of tokens, e.g.
    memory-store
  - :resource-tokens or :introspect-pred, as introspection-handler has
    them
  - :authorize and :error-page, as above"
  [opts]
  (let [{:keys [authorize] :as opts} (options opts)]
    (when-not (fn? authorize)
      (throw (ex-info "The authorization endpoint needs an :authorize function" {})))
    (ring/handler {:get     #(authorization-page % opts)
                   :post    #(endpoint/form-response % (fn [fields] (endpoint/profile-response fields opts)) opts)
                   :options (constantly ring/preflight)})))

;; TODO: Ticket Auth, https://indieweb.org/IndieAuth_Ticket_Auth, so that a
;; friend's reader gets a token for private posts: a ticket grant here, and
;; a handler for a ticket endpoint
(defn token-handler
  "A Ring handler for the token endpoint, by the `opts` of handler.

  A POST redeems a code for an access token, or a refresh token for new
  tokens, and a code without a scope for the :me alone. A refresh token
  works once, and one used again revokes its grant and all its tokens, as
  a code used again does. Older clients and resource servers can revoke
  and verify tokens here too, by the :legacy-revocation? and
  :legacy-verification? of default-options."
  [opts]
  (let [{:keys [legacy-verification?] :as opts} (options opts)]
    (ring/handler (cond-> {:post    #(endpoint/form-response % (fn [fields] (endpoint/token-response fields opts)) opts)
                           :options (constantly ring/preflight)}
                    legacy-verification? (assoc :get #(endpoint/legacy-verification % opts))))))

;; RFC 7009; IndieAuth 7
(defn revocation-handler
  "A Ring handler for the revocation endpoint, by the `opts` of handler.

  A POST revokes the token of its form: an access token alone, or a
  refresh token with its grant, and so with every token of the grant. It
  answers 200 whether it knew the token or not, as RFC 7009 says, and takes
  no client authentication, as section 4.1.1 has it."
  [opts]
  (let [opts (options opts)]
    (ring/handler {:post    #(endpoint/form-response % (fn [fields] (endpoint/revoked-response (get fields "token") opts))
                                                     opts)
                   :options (constantly ring/preflight)})))

;; IndieAuth 6; RFC 7662
(defn introspection-handler
  "A Ring handler for the introspection endpoint, by the `opts` of handler.

  A POST asks about the access token of its form, as RFC 7662 has it. A
  resource server asks with one of the :resource-tokens of `opts` as its
  bearer token, and you can wrap those with wary-fetch's secret/hide. Or
  else the :introspect-pred of `opts`, a function of the Ring request,
  says whether it may ask (section 6.1). Others get 401."
  [opts]
  (let [{:keys [introspect-pred resource-tokens] :as opts} (options opts)
        allowed? (or introspect-pred (endpoint/resource-pred resource-tokens))
        answer   (fn [{:strs [token]}]
                   (async/then (resource/token-info! token opts)
                               #(ring/json-response 200 (if % (endpoint/introspection %) {:active false}))))]
    (ring/handler {:post (fn [request]
                           (async/then (allowed? request)
                                       #(if %
                                          (endpoint/form-response request answer opts)
                                          (resource/problem-response
                                           {:status 401
                                            :code   "invalid_token"
                                            :reason "The request needs the token of a resource server"}))))})))

;; IndieAuth 9
(defn userinfo-handler
  "A Ring handler for the userinfo endpoint, by the `opts` of handler.

  A GET or a POST with an access token that has the profile scope gives the
  JSON of the user's profile information, as the token response had it. A
  request without a token gets 401, and one whose token doesn't have the
  scope 403, as section 8.1 has it."
  [opts]
  (let [{:keys [tokens cors?] :as opts} (options opts)
        answer (fn [request]
                 (async/then (resource/access! request ["profile"] opts)
                             (fn [{:keys [error response grant]}]
                               (if error
                                 (ring/with-cors response cors?)
                                 (async/then ((:get tokens) (grant/grant-key grant))
                                             #(endpoint/json-answer (or (:profile %) {}) opts))))))]
    (ring/handler {:get     answer
                   :post    answer
                   :options (constantly ring/preflight)})))

;;; metadata and links

;; IndieAuth 4.1.1; RFC 8414, section 2
(defn metadata
  "The metadata document of the server of the `opts` of handler, as a map
  of its JSON.

  The :metadata-url of `opts` is the URL where you serve it, the
  well-known URL of RFC 8414 by default. The issuer must be a prefix of
  it, as section 3.1 says, or it throws. The :service-documentation of
  `opts`, a URL, is listed too when it's given, and so are the endpoints
  that `opts` name."
  [opts]
  (let [{:keys [issuer authorization-endpoint token-endpoint metadata-url
                revocation-endpoint introspection-endpoint userinfo-endpoint
                refresh-seconds scopes-supported service-documentation]}
        (options opts)
        metadata-url (or metadata-url (indieauth/well-known-url issuer))]
    (when-not (indieauth/issuer-of? issuer metadata-url)
      (throw (ex-info "The :issuer isn't a prefix of the :metadata-url"
                      {:issuer issuer :metadata-url metadata-url})))
    (cond-> {:issuer                                         issuer
             :authorization_endpoint                         authorization-endpoint
             :scopes_supported                               (vec scopes-supported)
             :response_types_supported                       ["code"]
             :grant_types_supported                          (cond-> ["authorization_code"]
                                                               refresh-seconds (conj "refresh_token"))
             :code_challenge_methods_supported               ["S256"]
             :authorization_response_iss_parameter_supported true}
      token-endpoint         (assoc :token_endpoint token-endpoint)
      ;; IndieAuth 4.1.1: no client authentication for revocation
      revocation-endpoint    (assoc :revocation_endpoint revocation-endpoint
                                    :revocation_endpoint_auth_methods_supported ["none"])
      introspection-endpoint (assoc :introspection_endpoint introspection-endpoint)
      userinfo-endpoint      (assoc :userinfo_endpoint userinfo-endpoint)
      service-documentation  (assoc :service_documentation service-documentation))))

(defn metadata-handler
  "A Ring handler that serves the metadata document of the server of the
  `opts` of handler, which a page in any browser can read, by :cors?."
  [opts]
  (let [{:keys [cors?] :as opts} (options opts)
        document (constantly (ring/with-cors (ring/response 200 "application/json"
                                                            (json/write-json (metadata opts)))
                                             cors?))]
    (ring/handler {:get     document
                   :head    document
                   :options (constantly ring/preflight)})))

;; IndieAuth 4.1
(defn links
  "The links that name the server of the `opts` of handler on a profile
  page, as maps of :rel and :href, e.g. for the link elements in its head:
  indieauth-metadata, and authorization_endpoint and token_endpoint for
  older clients."
  [opts]
  (let [{:keys [issuer authorization-endpoint token-endpoint metadata-url]} (options opts)]
    (cond-> [{:rel "indieauth-metadata" :href (or metadata-url (indieauth/well-known-url issuer))}
             {:rel "authorization_endpoint" :href authorization-endpoint}]
      token-endpoint (conj {:rel "token_endpoint" :href token-endpoint}))))

;; RFC 8288, section 3
(defn link-header
  "The value of a Link header that names the server of the `opts` of
  handler, with the links of links, e.g. for the answer to a request for a
  profile page."
  [opts]
  (->> (links opts)
       (map (fn [{:keys [rel href]}] (str "<" href ">; rel=\"" rel "\"")))
       (str/join ", ")))

;;; profile information

;; IndieAuth 5.3.4
(defn profile
  "The profile information on the HTML page of a user in the `response`,
  from its representative h-card, as a map of the :name, :url, :photo and
  :email that it has, or nil. The client gets it with the profile scope,
  and the email with the email scope too."
  [{:keys [url body] :as response}]
  (when (string? body)
    (info/page-profile body url)))

(defn profile!
  "Fetch the page of the profile URL `me` with `opts`, and give its
  profile information as profile does, or nil when it can't be read. In
  ClojureScript, it gives a promise."
  ([me]
   (profile! me {}))
  ([me opts]
   (let [{:keys [max-page-bytes] :as opts} (merge default-options opts)]
     (async/then (fetch/get! me "text/html" max-page-bytes opts)
                 #(when-not (:error %) (profile %))))))
