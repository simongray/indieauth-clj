(ns dk.simongray.indieauth.server
  "An IndieAuth server: the authorization, token, revocation,
  introspection and userinfo endpoints and the metadata document.

  Signing the user in and asking for their consent are yours to do. The
  authorization endpoint checks a client's request and gives it to a
  function of yours, which signs the user in by any means and shows the
  consent page with what consent gives. Then approve! checks the answer
  and gives the client its code. Codes and tokens are kept in stores of
  yours, maps of a few functions, or in memory-store, and only their
  hashes are kept. In ClojureScript, the handlers answer with promises,
  and a server gives them a body that it has read.

  The code follows the IndieAuth Living Standard of 11 July 2024 at
  https://indieauth.spec.indieweb.org/ and cites its sections. A resource
  server checks the tokens with dk.simongray.indieauth.resource."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.links :as links]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.microformats :as mf]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

(def default-options
  "The default of each option of a server that has one, which follows
  IndieAuth:

  - :scopes-supported, the scopes that the metadata lists, profile and
    email. Add those of your resource servers, e.g. create for Micropub.
  - :code-seconds, 60: how long a code lasts, well within the 10 minutes
    that section 5.2.1 recommends at most
  - :token-seconds, 86400: how long an access token lasts, a day, or for
    ever when nil. Section 5.5 recommends short-lived tokens with refresh
    tokens.
  - :refresh-seconds, 2592000: how long a refresh token lasts unused, 30
    days, since section 5.5 says that one should expire when a client
    has been inactive. Nil gives no refresh tokens.
  - :legacy-revocation?, true: the token endpoint revokes a token with
    action=revoke, as earlier versions of IndieAuth had it
  - :legacy-verification?, false: the token endpoint verifies a token
    with a GET, as the W3C Note of 2018 had it, for older resource
    servers. It tells anyone who has a token whose it is, which is why
    introspection replaced it, so turn it on only for one that needs it.
  - :request-seconds, 1800: how long a user has to sign in and say yes
  - :client-info?, true: the client identifier is fetched for the
    client's name, logo and redirect URLs, as section 4.2 advises
  - :client-id-pred, indieauth/client-id?, the client identifiers that
    the server takes, as section 3.3 has them
  - :profile-url-pred, indieauth/profile-url?, the URLs that a user can
    sign in as, as section 3.2 has them
  - :cors?, true: a client in a browser can read the metadata and redeem
    its code
  - :timeout-seconds, 10: the limit of each request to a client
  - :max-page-bytes, 2 MB, and :max-json-bytes, 256 kB: the largest
    page and JSON document at a client identifier
  - :max-form-bytes, 64 kB: the largest form that a client posts
  - :send, http/send-public!, which sends to the public internet alone,
    so that a client identifier on the server's own network isn't
    fetched, as section 4.2 says
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
  "A store in the atom `a`, or in a new one, as a map of keys to values,
  which drops each value once the instant that `now-fn` gives passes its
  :expires.

  A store is a map of functions, which can give their results as promises
  in ClojureScript:

  - :put!, a function of a key and a value that keeps the value
  - :get, a function of a key that gives its value, or nil
  - :take!, a function of a key that gives its value and removes it in one
    step, so that two calls never both get it
  - :delete!, a function of a key that removes its value

  The store of codes needs :put! and :take!, and the store of tokens all
  four. A key is the SHA-256 of a code or a token, never the text itself.
  A value is a map that can have :expires, an instant after which it's of
  no use, which a store can drop."
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

(defn- each!
  "Call `f` on each of `xs` in turn, after what the call before gives, a
  value, a future or a promise, is there."
  [f xs]
  (reduce (fn [acc x] (async/then acc (fn [_] (f x)))) nil xs))

;;; client information

(defn- loopback?
  "Whether the client identifier `client-id` names a loopback host, which
  section 4.2 says not to fetch."
  [client-id]
  (let [host (:host (indieauth/url-parts client-id))]
    (boolean (or (contains? indieauth/loopback-hosts host)
                 (re-find #"(?i)(^|\.)localhost\.?$" (str host))))))

(defn- unknown-client
  "The client information of the `client-id` alone."
  [client-id]
  {:client-id client-id :redirect-uris []})

(defn- property
  "The first value of the property `k` of the microformat `item`, the URL
  of an image with alt text too, or nil."
  [item k]
  (let [v (first (get-in item [:properties k]))]
    (cond
      (string? v) v
      (map? v)    (when (string? (:value v)) (:value v)))))

;; IndieAuth 4.2.1 and its note on h-app
(defn- app-info
  "The client information in the HTML page of the `response` from
  `client-id`: its first h-app, and its redirect URLs, from its Link
  headers and the link elements in its head, as section 4.2.2 names them."
  [client-id {:keys [url body] :as response}]
  (let [nodes (html/parse body)
        apps  (->> (:items (mf/parse nodes url))
                   (mapcat #(tree-seq map? :children %))
                   (filter #(some #{"h-app" "h-x-app"} (:type %))))
        app   (or (first (filter #(= client-id (some-> (property % :url) indieauth/canonical-url))
                                 apps))
                  (first apps))]
    (cond-> (assoc (unknown-client client-id)
                   :redirect-uris (vec (links/hrefs "redirect_uri" (links/links response nodes {}))))
      (property app :name) (assoc :client-name (property app :name))
      (property app :url)  (assoc :client-uri (property app :url))
      (property app :logo) (assoc :logo-uri (property app :logo)))))

;; IndieAuth 4.2.1; OAuth Client ID Metadata Document
(defn- document-info
  "The client information in the client metadata document `m` from
  `client-id`, or nil when the document names another client, which
  section 4.2.1 says not to trust."
  [client-id {:keys [client_name client_uri logo_uri redirect_uris] :as m}]
  (when (= client-id (some-> (:client_id m) str indieauth/canonical-url))
    (let [text? #(and (string? %) (seq %))]
      (cond-> (assoc (unknown-client client-id)
                     :redirect-uris (filterv string? (when (sequential? redirect_uris)
                                                       redirect_uris)))
        (text? client_name)     (assoc :client-name client_name)
        ;; the page about a client is a prefix of its identifier
        (and (text? client_uri)
             (str/starts-with? client-id client_uri))
        (assoc :client-uri client_uri)
        (url/web-url? logo_uri) (assoc :logo-uri logo_uri)))))

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
               (json/read-object body))]
    (cond
      m
      (or (document-info client-id m) (unknown-client client-id))

      (and (string? body) (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (app-info client-id response)

      :else
      (unknown-client client-id))))

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
     (if (loopback? client-id)
       (async/then (unknown-client client-id) identity)
       (async/then
        (async/attempt #(http/fetch! client-id (assoc opts
                                                      :accept "application/json, text/html;q=0.9"
                                                      :max-bytes max-page-bytes)))
        (fn [{{:keys [status] :as response} :value error :error}]
          (cond
            error
            (assoc (unknown-client client-id) :error (http/failure error))

            (not (ring/success? status))
            (assoc (unknown-client client-id)
                   :error {:reason (str client-id " answered " status) :status status})

            :else
            (client-info client-id response))))))))

;;; the authorization request

(def ^:no-doc unsafe-schemes
  "The schemes of URLs that are never a redirect URL, since a browser runs
  them or shows a local file."
  #{"javascript" "data" "vbscript" "file" "blob"})

(defn- redirect-uri-problem
  "What's wrong with `s` as a redirect URL, or nil."
  [s]
  (let [{:keys [scheme fragment]} (indieauth/url-parts s)]
    (cond
      (nil? scheme)                            "redirect_uri isn't an absolute URL"
      (some? fragment)                         "redirect_uri has a fragment"
      (contains? unsafe-schemes scheme)        "redirect_uri has a scheme that isn't allowed"
      (re-find indieauth/unsafe-characters s)  "redirect_uri has a space or a backslash"
      (and (#{"http" "https"} scheme)
           (not (url/web-url? s)))             "redirect_uri has no host")))

;; IndieAuth 5.2 and 10.1
(defn registered?
  "Whether the client of the client information `info` may have its
  browser sent to `redirect-uri`: one on the scheme, host and port of the
  client identifier, or one that the client lists, the same text."
  [{:keys [client-id redirect-uris] :as info} redirect-uri]
  (boolean (or (and (url/web-url? redirect-uri)
                    (url/same-origin? client-id redirect-uri))
               (some #{redirect-uri} redirect-uris))))

;; RFC 6749, section 4.1.2.1; RFC 9207, section 2
(defn- error-redirect
  "The URL that sends the browser back to the `redirect-uri` of a client
  with the error `code` and `description`, the `state` and the `issuer`."
  [redirect-uri state issuer code description]
  (url/with-query redirect-uri [["error" code]
                                ["error_description" description]
                                ["state" state]
                                ["iss" issuer]]))

(defn- repeated-field
  "The name of a field that comes more than once in the single-valued
  `fields`, or nil."
  [fields]
  (some (fn [[k v]] (when (= ::ring/repeated v) k)) fields))

;; IndieAuth 5.2; RFC 7636, section 4.3
(defn- pkce-problem
  "What's wrong with the PKCE `challenge` and `method` of a request, or
  nil. Only S256 is taken, and a request without PKCE isn't."
  [challenge method]
  (cond
    (nil? challenge)                                  "code_challenge is missing"
    (not= "S256" method)                              "code_challenge_method must be S256"
    (not (re-matches #"[A-Za-z0-9_-]{43}" challenge)) "code_challenge isn't an S256 challenge"))

(defn- request-error
  "The :error of the request with the single-valued `fields` whose
  redirect URL is the client's, by the :issuer of `opts`, or nil. It
  sends the browser back to the client with the error, as its :redirect."
  [fields {:keys [issuer] :as opts}]
  (let [{:strs [response_type state code_challenge code_challenge_method
                scope redirect_uri]} fields
        repeated (repeated-field fields)
        asked    (when-not repeated (indieauth/scopes scope))
        [code reason]
        (cond
          repeated
          ["invalid_request" (str repeated " is repeated")]

          ;; RFC 9700, section 2.1.2: the code flow alone
          (not= "code" response_type)
          ["unsupported_response_type" "response_type must be code"]

          (empty? state)
          ["invalid_request" "state is missing"]

          (pkce-problem code_challenge code_challenge_method)
          ["invalid_request" (pkce-problem code_challenge code_challenge_method)]

          (nil? asked)
          ["invalid_scope" "scope has a scope that isn't valid"]

          (indieauth/profile-scope-problem asked)
          ["invalid_scope" (indieauth/profile-scope-problem asked)])]
    (when code
      {:error {:code     code
               :reason   reason
               :redirect (error-redirect redirect_uri (when (string? state) state)
                                         issuer code reason)}})))

(defn- authorization-request
  "The authorization request of the single-valued `fields`, from the
  client of the client information `info`, as a map of the :request or the
  :error, by `opts`."
  [fields info opts]
  (let [{:strs [redirect_uri state code_challenge scope me]} fields]
    (if-not (registered? info redirect_uri)
      {:error {:code   "invalid_request"
               :reason "redirect_uri isn't one that the client lists"}}
      (or (request-error fields opts)
          {:request (cond-> {:client-id      (:client-id info)
                             :redirect-uri   redirect_uri
                             :state          state
                             :code-challenge code_challenge
                             :scopes         (indieauth/scopes scope)
                             :client         (dissoc info :redirect-uris)}
                      (indieauth/canonical-url me) (assoc :me (indieauth/canonical-url me)))}))))

(defn- client-problem
  "What's wrong with the client identifier and the redirect URL in the
  single-valued `fields`, which a server tells the user rather than the
  client, by the :client-id-pred of `opts`, or nil."
  [fields {:keys [client-id-pred] :as opts}]
  (let [{:strs [client_id redirect_uri]} fields]
    (cond
      (= ::ring/repeated client_id)    "client_id is repeated"
      (= ::ring/repeated redirect_uri) "redirect_uri is repeated"
      (nil? client_id)                 "client_id is missing"
      (not (client-id-pred client_id)) "client_id isn't a valid client identifier"
      (nil? redirect_uri)              "redirect_uri is missing"
      :else                            (redirect-uri-problem redirect_uri))))

;; IndieAuth 5.2, 4.2 and 10.1; RFC 6749, section 4.1.2.1
(defn authorization-request!
  "Check the authorization request of a client with the query `fields`, a
  map by name or pairs of a name and a value, by `opts`, and give the
  :request, or the :error. In ClojureScript, it gives a promise.

  The request is a map:

  - :client-id, the client identifier, in canonical form
  - :redirect-uri, :state and :code-challenge, as the client sent them
  - :scopes, the scopes that the client asks for, a vector
  - :me, the profile URL that the client gave as a hint, in canonical
    form, which nobody has checked
  - :client, the client information of client-info!, without the
    redirect URLs, to show the user

  The client identifier is fetched for its client information, unless
  :client-info? is false, and a redirect URL on another scheme, host or
  port must be among those it lists. An error has the :code of OAuth 2.0,
  e.g. invalid_request, and the :reason. When the client and its
  redirect URL are known, it has the :redirect too, the URL to send the
  browser back to with the error, and else you show the user the reason.
  Only PKCE with S256 is taken. The `opts` are those of handler."
  [fields opts]
  (let [{:keys [client-info?] :as opts} (options opts)
        fields       (ring/single-values (if (map? fields) (ring/param-fields fields) fields))
        client-id    (indieauth/canonical-url (get fields "client_id"))
        redirect-uri (get fields "redirect_uri")]
    (if-let [problem (client-problem fields opts)]
      (async/then {:error {:code "invalid_request" :reason problem}} identity)
      (async/then (if (or client-info? (not (url/same-origin? client-id redirect-uri)))
                    (client-info! client-id opts)
                    (unknown-client client-id))
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

  The page names the client by its :client-id, and by its :client-name,
  :client-uri and :logo-uri from the :client, if it has them. It lists the
  :scopes, and lets the user grant fewer. The token is signed for `me`
  alone, so that it's also the token against cross-site requests of the
  page's form."
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
  (error-redirect redirect-uri state issuer "access_denied" "The user didn't consent"))

(defn- granted-scopes
  "The scopes of the `request` that the user grants, among `scopes`, all
  of them when nil. The email scope goes with the profile scope alone."
  [request scopes]
  (let [asked  (:scopes request)
        chosen (if (nil? scopes) asked (filterv (set scopes) asked))]
    (if (some #{"profile"} chosen)
      (vec chosen)
      (filterv #(not= "email" %) chosen))))

;; IndieAuth 5.3.4
(defn- granted-profile
  "The `profile` information of the user that the `scopes` grant: the
  :name, :url and :photo with profile, and the :email with email too."
  [profile scopes]
  (when (and (map? profile) (some #{"profile"} scopes))
    (not-empty
     (into {}
           (filter (fn [[_ v]] (and (string? v) (seq v))))
           (select-keys profile (cond-> [:name :url :photo]
                                  (some #{"email"} scopes) (conj :email)))))))

;; IndieAuth 5.2.1
(defn approve!
  "Give the client of the consent `token` a code for the `grant` of the
  user who said yes, by `opts`, and give the URL to send the browser back
  to, as a map of the :redirect, or of the :error. In ClojureScript, it
  gives a promise.

  The grant is a map:

  - :me, the profile URL of the user who is signed in, who must be the one
    that consent gave the token to
  - :scopes, the scopes that the user grants, among those that the client
    asked for, all of them when nil
  - :profile, the user's profile information, a map of :name, :url,
    :photo and :email, which the client gets with the profile scope, the
    email with the email scope too

  The code lasts :code-seconds, and works once, for the client
  identifier, the redirect URL and the PKCE challenge of the request. Its
  hash goes to the :put! of the :codes store of `opts`."
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
            granted (granted-scopes request scopes)
            shared  (granted-profile profile granted)]
        (async/then ((:put! codes) (bytes/hash-text code)
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

;;; grants and tokens

;; A grant is what a user granted a client with a code. Its access and
;; refresh tokens belong to it, so that revoking it revokes them all. The
;; store of tokens keeps it under a key of its own, with the keys of its
;; tokens and when each expires.

(defn- grant-key
  "The key of the grant `id` in a store of tokens, which no hash can be."
  [id]
  (str "grant:" id))

(defn- latest
  "The latest of the instants `xs`, or nil when one of them is nil, which
  is never."
  [xs]
  (when (every? some? xs)
    (apply max-key inst-ms xs)))

(defn- revoke-grant!
  "Delete the grant `id`, and each of its tokens, from the :tokens store of
  `opts`."
  [id {:keys [tokens] :as opts}]
  (async/then ((:get tokens) (grant-key id))
              (fn [grant]
                (each! (:delete! tokens) (conj (vec (keys (:tokens grant))) (grant-key id))))))

;; IndieAuth 5.3.2
(defn- profile-answer
  "The answer to the redemption of the code of `entry` for the profile URL
  alone."
  [{:keys [me profile] :as entry}]
  (cond-> {:me me}
    profile (assoc :profile profile)))

;; IndieAuth 5.3.3 and 5.5; RFC 6749, section 5.1
(defn- issue-tokens!
  "Issue an access token of the `scope` for the `grant` of `id`, a map of
  :me, :client-id, :scope, :profile and the :tokens it has, and a refresh
  token by the :refresh-seconds of `opts`, keep them in its :tokens store
  with the grant, and give the answer of the token endpoint."
  [id {:keys [me client-id profile] :as grant} scope
   {:keys [tokens token-seconds refresh-seconds now-fn] :as opts}]
  (let [at      (now-fn)
        access  (indieauth/token)
        refresh (when refresh-seconds (indieauth/token))
        entries (cond-> {(bytes/hash-text access) {:type      :access
                                                   :grant     id
                                                   :me        me
                                                   :client-id client-id
                                                   :scope     scope
                                                   :issued-at at
                                                   :expires   (some->> token-seconds (instant/later at))}}
                  refresh (assoc (bytes/hash-text refresh) {:type      :refresh
                                                            :grant     id
                                                            :client-id client-id
                                                            :scope     (:scope grant)
                                                            :expires   (instant/later at refresh-seconds)}))
        live    (into (update-vals entries :expires)
                      (remove #(some-> (val %) (instant/past? at)))
                      (:tokens grant))]
    (async/then (each! (fn [[k v]] ((:put! tokens) k v))
                       (assoc entries (grant-key id) (assoc grant
                                                            :tokens  live
                                                            :expires (latest (vals live)))))
                (fn [_]
                  (cond-> {:me           me
                           :access_token access
                           :token_type   "Bearer"
                           :scope        scope}
                    (and profile (some #{"profile"} (indieauth/scopes scope))) (assoc :profile profile)
                    token-seconds (assoc :expires_in token-seconds)
                    refresh       (assoc :refresh_token refresh))))))

;;; redemption, refresh and revocation

(defn- grant-error
  "The :error of an OAuth 2.0 token request of the `code` and the
  `reason`."
  [code reason]
  {:error {:code code :reason reason}})

;; IndieAuth 5.3.1; RFC 7636, section 4.6
(defn- code-problem
  "What's wrong with the `entry` of a code, redeemed with the single-valued
  `fields` at the instant `at`, or nil."
  [entry fields at]
  (let [{:strs [client_id redirect_uri code_verifier]} fields]
    (cond
      (nil? entry)                                          "The code is unknown, or used"
      (instant/expired? entry at)                           "The code has expired"
      (not= (:client-id entry) (indieauth/canonical-url client_id)) "The code is another client's"
      (not= (:redirect-uri entry) redirect_uri)             "The redirect_uri isn't that of the request"
      (not (indieauth/code-verifier? code_verifier))        "The code_verifier is missing, or not one"
      (not (bytes/same-text? (indieauth/code-challenge code_verifier) (:code-challenge entry)))
      "The code_verifier doesn't fit the code_challenge")))

;; RFC 6749, sections 4.1.2 and 10.5; RFC 9700, section 4.5: a code used
;; again revokes the tokens that it gave
(defn- redeem-code!
  "The entry of the code that the single-valued `fields` redeem, taken from
  the :codes store of `opts`, with its :key, or the :error. A code is taken
  before it's checked, so that it works once, even with a wrong verifier.
  A code used before revokes the grant of its tokens."
  [fields {:keys [codes now-fn] :as opts}]
  (let [{:strs [code client_id redirect_uri]} fields
        k (bytes/hash-text (str code))]
    (if (some empty? [code client_id redirect_uri])
      (async/then (grant-error "invalid_request" "code, client_id and redirect_uri are needed")
                  identity)
      (async/then
       ((:take! codes) k)
       (fn [entry]
         (if (:used? entry)
           (async/then (some-> (:grant entry) (revoke-grant! opts))
                       (constantly (grant-error "invalid_grant"
                                                "The code was used before, so its tokens are revoked")))
           (if-let [problem (code-problem entry fields (now-fn))]
             (grant-error "invalid_grant" problem)
             {:key k :entry entry})))))))

(defn- used!
  "Keep in the :codes store of `opts` that the code of key `k` and `entry`
  was used, with the `grant` id of its tokens, if any, until it would have
  expired."
  [k entry grant {:keys [codes] :as opts}]
  ((:put! codes) k (cond-> {:used? true :expires (:expires entry)}
                     grant (assoc :grant grant))))

(defn- code-answer!
  "The answer of the token endpoint to the redemption of the code of key
  `k` and `entry`, by `opts`: tokens for a code with a scope, and else
  the profile URL alone, as section 5.3.3 says."
  [{k :key {:keys [me client-id scopes profile] :as entry} :entry} opts]
  (if (empty? scopes)
    (async/then (used! k entry nil opts) (constantly (profile-answer entry)))
    (let [id    (indieauth/token 16)
          scope (indieauth/scope-text scopes)]
      (async/then (issue-tokens! id {:me me :client-id client-id :scope scope :profile profile}
                                 scope opts)
                  (fn [answer]
                    (async/then (used! k entry id opts) (constantly answer)))))))

;; IndieAuth 5.5.1; RFC 6749, section 6
(defn- refresh-problem
  "What's wrong with refreshing the refresh token of `entry` with the
  single-valued `fields` at the instant `at`, as a pair of the error code
  and the reason, or nil."
  [entry fields at]
  (let [{:strs [client_id scope]} fields
        asked (indieauth/scopes scope)]
    (cond
      (not= :refresh (:type entry))
      ["invalid_grant" "The refresh token is unknown, or revoked"]

      (instant/expired? entry at)
      ["invalid_grant" "The refresh token has expired"]

      (not= (:client-id entry) (indieauth/canonical-url client_id))
      ["invalid_grant" "The refresh token is another client's"]

      (nil? asked)
      ["invalid_scope" "scope has a scope that isn't valid"]

      (not-every? (set (indieauth/scopes (:scope entry))) asked)
      ["invalid_scope" "scope asks for more than was granted"])))

(defn- rotate!
  "Replace the refresh token of key `k` and `entry`, which has just been
  taken from the :tokens store of `opts`, with new tokens of the `scopes`,
  or of the grant's when they're empty, and keep that the old one was
  used."
  [k {:keys [grant] :as entry} scopes {:keys [tokens] :as opts}]
  (async/then ((:get tokens) (grant-key grant))
              (fn [g]
                (if (nil? g)
                  (grant-error "invalid_grant" "The grant is revoked")
                  (async/then ((:put! tokens) k (assoc entry :used? true))
                              (fn [_]
                                (issue-tokens! grant g
                                               (or (indieauth/scope-text scopes) (:scope g))
                                               opts)))))))

;; IndieAuth 5.5.1; RFC 9700, section 4.14.2: a refresh token used again
;; revokes its grant
(defn- refresh-answer!
  "The answer of the token endpoint to the refresh of the single-valued
  `fields`, by the :tokens store of `opts`, or the :error."
  [fields {:keys [tokens now-fn] :as opts}]
  (let [{:strs [refresh_token client_id scope]} fields
        k (bytes/hash-text (str refresh_token))]
    (if (some empty? [refresh_token client_id])
      (async/then (grant-error "invalid_request" "refresh_token and client_id are needed")
                  identity)
      (async/then
       ((:get tokens) k)
       (fn [entry]
         (let [[code reason] (refresh-problem entry fields (now-fn))]
           (cond
             (and (= :refresh (:type entry)) (:used? entry))
             (async/then (revoke-grant! (:grant entry) opts)
                         (constantly (grant-error "invalid_grant"
                                                  "The refresh token was used before, so its grant is revoked")))

             code
             (grant-error code reason)

             :else
             (async/then ((:take! tokens) k)
                         #(if %
                            (rotate! k % (indieauth/scopes scope) opts)
                            (grant-error "invalid_grant" "The refresh token is unknown, or revoked"))))))))))

;; RFC 7009, section 2.1; IndieAuth 7
(defn- revoke!
  "Revoke the `token` by the :tokens store of `opts`: an access token
  alone, or a refresh token with its grant and every token of the grant.
  Another text does nothing."
  [token {:keys [tokens] :as opts}]
  (let [k (bytes/hash-text (str token))]
    (async/then ((:get tokens) k)
                (fn [entry]
                  (case (:type entry)
                    :access  ((:delete! tokens) k)
                    :refresh (revoke-grant! (:grant entry) opts)
                    nil)))))

;;; responses

(defn- error-response
  "The Ring response of an OAuth 2.0 `error`, a map of the :code and the
  :reason, by the :cors? of `opts`."
  [{:keys [code reason] :as error} {:keys [cors?] :as opts}]
  (ring/with-cors (ring/json-response 400 {:error code :error_description reason}) cors?))

(defn- json-answer
  "The Ring response of 200 with the JSON of `x`, by the :cors? of `opts`."
  [x {:keys [cors?] :as opts}]
  (ring/with-cors (ring/json-response 200 x) cors?))

(defn- answered
  "The Ring response of the `answer` of an endpoint, or of its :error, by
  `opts`."
  [{:keys [error] :as answer} opts]
  (if error
    (error-response error opts)
    (json-answer answer opts)))

(defn- form-response
  "The Ring response to the POST `request` of a form, which `f`, a function
  of its single-valued fields, answers, by the :max-form-bytes of `opts`."
  [request f {:keys [max-form-bytes] :as opts}]
  (if-let [pairs (ring/form-fields request max-form-bytes)]
    (let [fields (ring/single-values pairs)]
      (if-let [repeated (repeated-field fields)]
        (error-response {:code "invalid_request" :reason (str repeated " is repeated")} opts)
        (f fields)))
    (assoc (error-response {:code "invalid_request" :reason "The form is too large"} opts)
           :status 413)))

;; IndieAuth 5.3.2
(defn- profile-response
  "The Ring response of the authorization endpoint to the redemption of a
  code with the single-valued `fields`, by `opts`. The redemptions of older
  clients have no grant_type."
  [fields opts]
  (if (contains? #{nil "authorization_code"} (get fields "grant_type"))
    (async/then (redeem-code! fields opts)
                (fn [{:keys [error key entry] :as redeemed}]
                  (if error
                    (error-response error opts)
                    (async/then (used! key entry nil opts)
                                (fn [_] (json-answer (profile-answer entry) opts))))))
    (error-response {:code "unsupported_grant_type" :reason "grant_type must be authorization_code"}
                    opts)))

(defn- revoked-response
  "The Ring response to the revocation of the `token`, by `opts`: 200
  whether it was known or not, as RFC 7009, section 2.2, says."
  [token {:keys [cors?] :as opts}]
  (if (and (string? token) (seq token))
    (async/then (revoke! token opts)
                (fn [_] (ring/with-cors (ring/text-response 200 "") cors?)))
    (error-response {:code "invalid_request" :reason "token is missing"} opts)))

;; IndieAuth 5.3.3, 5.5.1 and 7
(defn- token-response
  "The Ring response of the token endpoint to a POST of the single-valued
  `fields`, by `opts`. An older client revokes a token here with
  action=revoke, by :legacy-revocation?."
  [fields {:keys [refresh-seconds legacy-revocation?] :as opts}]
  (let [{:strs [grant_type action token]} fields]
    (cond
      (and legacy-revocation? (= "revoke" action))
      (revoked-response token opts)

      (nil? grant_type)
      (error-response {:code "invalid_request" :reason "grant_type is missing"} opts)

      (= "authorization_code" grant_type)
      (async/then (redeem-code! fields opts)
                  (fn [{:keys [error] :as redeemed}]
                    (if error
                      (error-response error opts)
                      (async/then (code-answer! redeemed opts) #(answered % opts)))))

      (and refresh-seconds (= "refresh_token" grant_type))
      (async/then (refresh-answer! fields opts) #(answered % opts))

      :else
      (error-response {:code   "unsupported_grant_type"
                       :reason (str "grant_type must be authorization_code"
                                    (when refresh-seconds " or refresh_token"))}
                      opts))))

;; The W3C Note of IndieAuth of 23 January 2018, section 6.3.4
(defn- legacy-verification
  "The answer of the token endpoint to an older resource server's GET
  `request`, which verifies the bearer token of its Authorization header,
  by `opts`."
  [request opts]
  (async/then (resource/access! request [] opts)
              (fn [{:keys [error response me client-id scope]}]
                (if error
                  response
                  (ring/json-response 200 {:me me :client_id client-id :scope scope})))))

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

(defn handler
  "A Ring handler for the authorization endpoint, by `opts`.

  A GET is a client's authorization request, which authorization-request!
  checks. When it's right, the handler answers with what the :authorize of
  `opts` gives, a function of the Ring request and the checked request,
  e.g. a page that signs the user in, or the consent page. When it's
  wrong, the browser goes back to the client with the error, or the
  :error-page of `opts` tells the user, a function of the Ring request and
  the :error.

  A POST redeems a code for the profile URL alone, and the JSON of the
  answer has the :me, and the :profile when the user granted it.

  The `opts` are those of default-options, and these:

  - :issuer, the issuer identifier, an https URL that is a prefix of the
    URL of the metadata, as section 3.1 says
  - :authorization-endpoint and :token-endpoint, their URLs, and
    :revocation-endpoint, :introspection-endpoint and :userinfo-endpoint,
    for those that you serve
  - :secret, a text of 32 bytes or more, e.g. a token, that signs the
    requests and consents of request-token and consent
  - :codes and :tokens, the stores of codes and of tokens, e.g.
    memory-store
  - :resource-tokens, the texts with which resource servers ask the
    introspection endpoint, which can be hidden texts, or :introspect-pred,
    as introspection-handler has it
  - :authorize and :error-page, as above"
  [opts]
  (let [{:keys [authorize] :as opts} (options opts)]
    (when-not (fn? authorize)
      (throw (ex-info "The authorization endpoint needs an :authorize function" {})))
    (ring/handler {:get     #(authorization-page % opts)
                   :post    #(form-response % (fn [fields] (profile-response fields opts)) opts)
                   :options (constantly ring/preflight)})))

(defn token-handler
  "A Ring handler for the token endpoint, by the `opts` of handler.

  A POST redeems a code for an access token, or a refresh token for a new
  one, as section 5.5 says. The JSON of the answer has :access_token,
  :token_type Bearer, :scope and :me, :profile when the user granted it,
  :expires_in by :token-seconds, and :refresh_token by :refresh-seconds. A
  code without a scope gives the :me alone, as section 5.3.3 says, and no
  cache keeps an answer.

  A refresh token works once, and its answer has a new one. One used
  again revokes the grant and all its tokens, as a code used again does.
  An older client can revoke a token here with action=revoke, by
  :legacy-revocation?. An older resource server can verify one with a GET
  and the token as its bearer token, by :legacy-verification?, and gets
  the JSON of its :me, :client_id and :scope, or 401. Since the GET needs
  no authorization of the resource server, as introspection does, anyone
  who has a token learns whether it's valid and whose it is."
  [opts]
  (let [{:keys [legacy-verification?] :as opts} (options opts)]
    (ring/handler (cond-> {:post    #(form-response % (fn [fields] (token-response fields opts)) opts)
                           :options (constantly ring/preflight)}
                    legacy-verification? (assoc :get #(legacy-verification % opts))))))

;; RFC 7009; IndieAuth 7
(defn revocation-handler
  "A Ring handler for the revocation endpoint, by the `opts` of handler.

  A POST revokes the token of its form: an access token alone, or a
  refresh token with its grant, and so with every token of the grant. It
  answers 200 whether it knew the token or not, as RFC 7009 says, and takes
  no client authentication, as section 4.1.1 has it."
  [opts]
  (let [opts (options opts)]
    (ring/handler {:post    #(form-response % (fn [fields] (revoked-response (get fields "token") opts))
                                            opts)
                   :options (constantly ring/preflight)})))

(defn- resource-pred
  "A function of a Ring request that says whether it has a bearer token
  among the `resource-tokens`, by their hashes, compared in a time that
  doesn't tell where they differ."
  [resource-tokens]
  (let [hashes (mapv #(bytes/hash-text (str (secret/reveal %))) resource-tokens)]
    (fn [request]
      (when-let [given (some-> (resource/header-token request) bytes/hash-text)]
        (boolean (some #(bytes/same-text? given %) hashes))))))

;; IndieAuth 6.2; RFC 7662, section 2.2
(defn- introspection
  "The answer of the introspection endpoint for the token information
  `info`."
  [{:keys [me client-id scope issued-at expires] :as info}]
  (cond-> {:active    true
           :me        me
           :client_id client-id
           :scope     scope
           :iat       (instant/epoch-seconds issued-at)}
    expires (assoc :exp (instant/epoch-seconds expires))))

;; IndieAuth 6; RFC 7662
(defn introspection-handler
  "A Ring handler for the introspection endpoint, by the `opts` of handler.

  A POST asks about the access token of its form, and the JSON of the
  answer has :active true, :me, :client_id, :scope, :iat and :exp, or
  :active false alone. Section 6.1 says that the endpoint needs
  authorization, so a resource server asks with one of the
  :resource-tokens of `opts` as its bearer token. Or else the
  :introspect-pred of `opts`, a function of the Ring request, says
  whether it may ask, and can give a promise in ClojureScript. A request
  that may not gets 401, which tells nothing about the token."
  [opts]
  (let [{:keys [introspect-pred resource-tokens] :as opts} (options opts)
        allowed? (or introspect-pred (resource-pred resource-tokens))
        answer   (fn [{:strs [token]}]
                   (async/then (resource/token-info! token opts)
                               #(ring/json-response 200 (if % (introspection %) {:active false}))))]
    (ring/handler {:post (fn [request]
                           (async/then (allowed? request)
                                       #(if %
                                          (form-response request answer opts)
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
                                 (async/then ((:get tokens) (grant-key grant))
                                             #(json-answer (or (:profile %) {}) opts))))))]
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

;; https://microformats.org/wiki/representative-h-card-parsing
(defn- representative-card
  "The representative h-card of the page at `url` whose microformats are
  `mf2`, or nil."
  [mf2 url]
  (let [cards (filter #(some #{"h-card"} (:type %)) (:items mf2))
        urls  #(set (keep indieauth/canonical-url (get-in % [:properties :url])))
        uids  #(set (keep indieauth/canonical-url (get-in % [:properties :uid])))
        me    (set (keep indieauth/canonical-url (get-in mf2 [:rels :me])))
        page  (indieauth/canonical-url url)]
    (or (first (filter #(and ((uids %) page) ((urls %) page)) cards))
        (first (filter #(some me (urls %)) cards))
        (when (= 1 (count cards))
          (first (filter #((urls %) page) cards))))))

;; IndieAuth 5.3.4
(defn profile
  "The profile information on the HTML page of a user in the `response`,
  from its representative h-card, as a map of the :name, :url, :photo and
  :email that it has, or nil. The client gets it with the profile scope,
  and the email with the email scope too."
  [{:keys [url body] :as response}]
  (when (string? body)
    (let [card (representative-card (mf/parse body url) url)]
      (not-empty
       (into {}
             (filter (fn [[_ v]] (and (string? v) (seq v))))
             {:name  (property card :name)
              :url   (property card :url)
              :photo (property card :photo)
              :email (some-> (property card :email) (str/replace #"(?i)^mailto:" ""))})))))

(defn profile!
  "Fetch the page of the profile URL `me` with `opts`, and give its
  profile information as profile does, or nil when it can't be read. In
  ClojureScript, it gives a promise."
  ([me]
   (profile! me {}))
  ([me opts]
   (let [{:keys [max-page-bytes] :as opts} (merge default-options opts)]
     (async/then (async/attempt #(http/fetch! me (assoc opts
                                                        :accept "text/html"
                                                        :max-bytes max-page-bytes)))
                 (fn [{{:keys [status] :as response} :value}]
                   (when (ring/success? status)
                     (profile response)))))))
