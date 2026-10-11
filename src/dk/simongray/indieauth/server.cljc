(ns dk.simongray.indieauth.server
  "An IndieAuth server: the authorization endpoint, the token endpoint and
  the metadata document, and the checks of an access token that a resource
  server such as a Micropub endpoint makes.

  Signing the user in and asking for their consent are yours to do. The
  authorization endpoint checks a client's request and gives it to a
  function of yours, which signs the user in by any means and shows the
  consent page with what consent gives. Then approve! checks the answer
  and gives the client its code. Codes and tokens are kept in stores of
  yours, maps of a few functions, or in memory-store, and only their
  hashes are kept.

  The code follows the IndieAuth Living Standard of 11 July 2024 at
  https://indieauth.spec.indieweb.org/ and cites its sections."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.links :as links]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.microformats :as mf]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.url :as url]))

(def default-options
  "The default of each option of a server that has one, which follows
  IndieAuth:

  - :scopes-supported, the scopes that the metadata lists, profile and
    email. Add those of your resource servers, e.g. create for Micropub.
  - :code-seconds, 60: how long a code lasts, well within the 10 minutes
    that section 5.2.1 recommends at most
  - :token-seconds, nil: how long an access token lasts, for ever when nil
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
  {:scopes-supported ["profile" "email"]
   :code-seconds     60
   :token-seconds    nil
   :request-seconds  1800
   :client-info?     true
   :client-id-pred   indieauth/client-id?
   :profile-url-pred indieauth/profile-url?
   :cors?            true
   :timeout-seconds  10
   :max-page-bytes   (* 2 1024 1024)
   :max-json-bytes   (* 256 1024)
   :max-form-bytes   (* 64 1024)
   :send             http/send-public!
   :now-fn           #?(:clj  #(java.util.Date.)
                        :cljs #(js/Date.))})

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

(defn- later
  "The instant `seconds` after the instant `at`."
  [at seconds]
  (let [ms (+ (inst-ms at) (* 1000 seconds))]
    #?(:clj  (java.util.Date. (long ms))
       :cljs (js/Date. ms))))

(defn- expired?
  "Whether the map `m` has :expires, an instant at or before the instant
  `at`."
  [m at]
  (boolean (some-> (:expires m) inst-ms (<= (inst-ms at)))))

;;; stores

(defn hash-key
  "The key under which a store keeps what belongs to the code or token
  `s`: its SHA-256 in the URL-safe letters of base64, so that the store
  never holds the code or the token itself."
  [s]
  (bytes/base64url (bytes/sha256 (bytes/encode s))))

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

  The store of codes needs :put! and :take!, and the store of tokens
  :put!, :get and :delete!. A value is a map that can have :expires, an
  instant after which it's of no use, which a store can drop."
  ([]
   (memory-store (atom {})))
  ([a]
   (memory-store a #?(:clj  #(java.util.Date.)
                      :cljs #(js/Date.))))
  ([a now-fn]
   (let [live #(into {} (remove (fn [[_ v]] (expired? v (now-fn)))) %)]
     {:put!    (fn [k v]
                 (swap! a #(assoc (live %) k v))
                 nil)
      :get     (fn [k]
                 (get @a k))
      :take!   (fn [k]
                 (let [[old _] (swap-vals! a dissoc k)]
                   (get old k)))
      :delete! (fn [k]
                 (swap! a dissoc k)
                 nil)})))

;;; client information

(defn- loopback?
  "Whether the client identifier `client-id` names a loopback host, which
  section 4.2 says not to fetch."
  [client-id]
  (let [host (:host (indieauth/authority-parts (:authority (indieauth/url-parts client-id))))]
    (boolean (or (contains? indieauth/loopback-hosts host)
                 (re-find #"(?i)(^|\.)localhost\.?$" (str host))))))

(defn- media-type
  "The media type of the `response`, in lower case."
  [response]
  (headers/media-type (headers/header (:headers response) "content-type")))

(defn- json-type?
  "Whether the media type `type` is that of JSON."
  [type]
  (boolean (some->> type (re-find #"^application/(.+\+)?json$"))))

(defn- property
  "The first value of the property `k` of the microformat `item`, the URL
  of an image with alt text too, or nil."
  [item k]
  (let [v (first (get-in item [:properties k]))]
    (cond
      (string? v) v
      (map? v)    (when (string? (:value v)) (:value v)))))

(defn- typed
  "The microformats of the parsed `mf2` of any of the `types`, those at the
  top first, then those inside them."
  [mf2 types]
  (->> (:items mf2)
       (mapcat #(tree-seq map? :children %))
       (filter #(some (set types) (:type %)))))

;; IndieAuth 4.2.1 and its note on h-app
(defn- app-info
  "The client information in the HTML page of the `response` from
  `client-id`: its first h-app, and its redirect URLs, from its Link
  headers and the link elements in its head, as section 4.2.2 names them."
  [client-id {:keys [url body] :as response}]
  (let [nodes (html/parse body)
        apps  (typed (mf/parse nodes url) ["h-app" "h-x-app"])
        app   (or (first (filter #(= client-id (some-> (property % :url)
                                                       indieauth/canonical-url))
                                 apps))
                  (first apps))]
    (cond-> {:client-id     client-id
             :redirect-uris (vec (links/rel-urls "redirect_uri" response nodes {}))}
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
      (cond-> {:client-id     client-id
               :redirect-uris (vec (filter string? (when (sequential? redirect_uris)
                                                     redirect_uris)))}
        (text? client_name)  (assoc :client-name client_name)
        ;; the page about a client is a prefix of its identifier
        (and (text? client_uri)
             (str/starts-with? client-id client_uri)) (assoc :client-uri client_uri)
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
  [client-id {:keys [body] :as response}]
  (let [type (media-type response)
        m    (when (or (json-type? type) (nil? type))
               (json/read-object body))]
    (cond
      m
      (or (document-info client-id m) {:client-id client-id :redirect-uris []})

      (and (string? body) (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (app-info client-id response)

      :else
      {:client-id client-id :redirect-uris []})))

(defn client-info!
  "Fetch the client identifier `client-id` with `opts`, and give its
  client information as client-info does, or the :client-id alone with
  the :error when it can't be read. A client identifier on a loopback host
  isn't fetched, as section 4.2 says. In ClojureScript, it gives a
  promise."
  ([client-id]
   (client-info! client-id {}))
  ([client-id opts]
   (let [{:keys [max-page-bytes] :as opts} (merge default-options opts)
         alone                             {:client-id client-id :redirect-uris []}]
     (if (loopback? client-id)
       (async/then nil (constantly alone))
       (async/then
        (async/attempt #(http/fetch! client-id
                                     (assoc opts
                                            :accept "application/json, text/html;q=0.9"
                                            :max-bytes max-page-bytes)))
        (fn [{:keys [value error]}]
          (cond
            error
            (assoc alone :error (http/failure error))

            (not (<= 200 (:status value) 299))
            (assoc alone :error {:reason (str client-id " answered " (:status value))
                                 :status (:status value)})

            :else
            (client-info client-id value))))))))

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
      (nil? scheme)                         "redirect_uri isn't an absolute URL"
      (some? fragment)                      "redirect_uri has a fragment"
      (contains? unsafe-schemes scheme)     "redirect_uri has a scheme that isn't allowed"
      (re-find #"[\x00-\x20\x7f\\]" s)      "redirect_uri has a space or a backslash"
      (and (#{"http" "https"} scheme)
           (not (url/web-url? s)))          "redirect_uri has no host")))

;; IndieAuth 5.2 and 10.1
(defn registered?
  "Whether the client of the client information `info` may have its
  browser sent to `redirect-uri`: one on the scheme, host and port of the
  client identifier, or one that the client lists, the same text."
  [{:keys [client-id redirect-uris] :as info} redirect-uri]
  (boolean (or (and (url/web-url? redirect-uri)
                    (url/same-origin? client-id redirect-uri))
               (some #{redirect-uri} redirect-uris))))

(defn- error-redirect
  "The URL that sends the browser back to the `redirect-uri` of a client
  with the error `code` and `description`, the `state` and the `issuer`."
  [redirect-uri state issuer code description]
  ;; RFC 6749, section 4.1.2.1; RFC 9207, section 2
  (url/with-query redirect-uri [["error" code]
                                ["error_description" description]
                                ["state" state]
                                ["iss" issuer]]))

(defn- error-for
  "The :error of the `code` and `reason` of a request, which goes back to
  the client at its `redirect-uri` with its `state`, by the :issuer of
  `opts`, unless the redirect URL is nil."
  [code reason redirect-uri state {:keys [issuer] :as opts}]
  {:error (cond-> {:code code :reason reason}
            redirect-uri (assoc :redirect (error-redirect redirect-uri state issuer
                                                          code reason)))})

;; IndieAuth 5.2; RFC 7636, section 4.3
(defn- pkce-problem
  "What's wrong with the PKCE `challenge` and `method` of a request, or
  nil. Only S256 is taken, and a request without PKCE isn't."
  [challenge method]
  (cond
    (nil? challenge)                               "code_challenge is missing"
    (not= "S256" method)                           "code_challenge_method must be S256"
    (not (re-matches #"[A-Za-z0-9_-]{43}" challenge)) "code_challenge isn't an S256 challenge"))

(defn- request-error
  "The :error of the request with the single-valued `fields` whose
  redirect URL is known to be the client's, by `opts`, or nil."
  [fields opts]
  (let [{:strs [response_type state code_challenge code_challenge_method
                scope redirect_uri]} fields
        repeated (some (fn [[k v]] (when (= ::ring/repeated v) k)) fields)
        scopes   (when-not (= ::ring/repeated scope) (indieauth/scopes scope))
        fail     #(error-for %1 %2 redirect_uri (when (string? state) state) opts)]
    (cond
      repeated
      (fail "invalid_request" (str repeated " is repeated"))

      ;; RFC 9700, section 2.1.2: the code flow alone
      (not= "code" response_type)
      (fail "unsupported_response_type" "response_type must be code")

      (empty? state)
      (fail "invalid_request" "state is missing")

      (pkce-problem code_challenge code_challenge_method)
      (fail "invalid_request" (pkce-problem code_challenge code_challenge_method))

      (nil? scopes)
      (fail "invalid_scope" "scope has a scope that isn't valid")

      (indieauth/profile-scope-problem scopes)
      (fail "invalid_scope" (indieauth/profile-scope-problem scopes)))))

(defn- authorization-request
  "The authorization request of the single-valued `fields`, from the
  client of the client information `info`, as a map of the :request or the
  :error, by `opts`."
  [fields info opts]
  (let [{:strs [redirect_uri state code_challenge scope me]} fields]
    (cond
      (not (registered? info redirect_uri))
      {:error {:code   "invalid_request"
               :reason "redirect_uri isn't one that the client lists"}}

      :else
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
        fields                          (ring/single-values (if (map? fields)
                                                              (ring/param-fields fields)
                                                              fields))
        problem                         (client-problem fields opts)
        client-id                       (indieauth/canonical-url (get fields "client_id"))
        redirect-uri                    (get fields "redirect_uri")]
    (if problem
      (async/then nil (constantly {:error {:code "invalid_request" :reason problem}}))
      (async/then (if (or client-info?
                          (not (url/same-origin? client-id redirect-uri)))
                    (client-info! client-id opts)
                    {:client-id client-id :redirect-uris []})
                  #(authorization-request (assoc fields "client_id" client-id) % opts)))))

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
  (let [{:keys [secret now-fn request-seconds]} (options opts)]
    (or (signed/unsign secret ::request token (now-fn) request-seconds)
        (some-> (signed/unsign secret ::consent token (now-fn) request-seconds)
                (dissoc :me)))))

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
        me                                       (indieauth/canonical-url me)
        m                                        (assoc request :me me)]
    (when-not (and me (profile-url-pred me))
      (throw (ex-info "The user isn't a profile URL" {:me me})))
    (assoc m :token (signed/sign secret ::consent m (now-fn)))))

;; RFC 6749, section 4.1.2.1; RFC 9207, section 2
(defn denial
  "The URL that sends the browser back to the client of the authorization
  `request` when the user says no, with the error access_denied, the state
  and the :issuer of `opts`."
  [{:keys [redirect-uri state] :as request} {:keys [issuer] :as opts}]
  (error-redirect redirect-uri state issuer "access_denied"
                  "The user didn't consent"))

(defn- granted-scopes
  "The scopes of the `request` that the user grants, among `scopes`, all
  of them when nil. The email scope goes with the profile scope alone."
  [request scopes]
  (let [asked  (:scopes request)
        chosen (if (nil? scopes) asked (filter (set scopes) asked))]
    (if (some #{"profile"} chosen)
      (vec chosen)
      (vec (remove #{"email"} chosen)))))

;; IndieAuth 5.3.4
(defn- granted-profile
  "The `profile` information of the user that the `scopes` grant: the
  :name, :url and :photo with profile, and the :email with email too."
  [profile scopes]
  (when (and (map? profile) (some #{"profile"} scopes))
    (not-empty
     (into {}
           (filter (fn [[k v]] (and (string? v) (seq v))))
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
  (let [{:keys [secret now-fn request-seconds code-seconds codes issuer
                profile-url-pred]
         :as   opts} (options opts)
        at      (now-fn)
        request (signed/unsign secret ::consent token at request-seconds)
        me      (indieauth/canonical-url me)]
    (cond
      (nil? request)
      (async/then nil (constantly {:error {:code   "invalid_request"
                                           :reason "The consent is too old, or not this server's"}}))

      (not (and me (= me (:me request)) (profile-url-pred me)))
      (async/then nil (constantly {:error {:code   "access_denied"
                                           :reason "The consent was given to another user"}}))

      :else
      (let [code    (indieauth/token)
            granted (granted-scopes request scopes)
            entry   (cond-> {:client-id      (:client-id request)
                             :redirect-uri   (:redirect-uri request)
                             :code-challenge (:code-challenge request)
                             :me             me
                             :scopes         granted
                             :expires        (later at code-seconds)}
                      (granted-profile profile granted)
                      (assoc :profile (granted-profile profile granted)))]
        (async/then ((:put! codes) (hash-key code) entry)
                    (fn [_]
                      {:redirect (url/with-query (:redirect-uri request)
                                   [["code" code]
                                    ["state" (:state request)]
                                    ["iss" issuer]])}))))))

;;; redemption

(defn- grant-error
  "The :error of an OAuth 2.0 token request of the `code` and the
  `reason`."
  [code reason]
  {:error {:code code :reason reason}})

;; IndieAuth 5.3.1; RFC 7636, section 4.6
(defn- entry-problem
  "What's wrong with the `entry` of a code, redeemed with the single-valued
  `fields` at the instant `at`, or nil."
  [entry fields at]
  (let [{:strs [client_id redirect_uri code_verifier]} fields]
    (cond
      (nil? entry)                     "The code is unknown, or used"
      (expired? entry at)              "The code has expired"
      (not= (:client-id entry)
            (indieauth/canonical-url client_id)) "The code is another client's"
      (not= (:redirect-uri entry)
            redirect_uri)              "The redirect_uri isn't that of the request"
      (not (indieauth/code-verifier? code_verifier)) "The code_verifier is missing, or not one"
      (not (bytes/same? (bytes/encode (indieauth/code-challenge code_verifier))
                        (bytes/encode (:code-challenge entry))))
      "The code_verifier doesn't fit the code_challenge")))

(defn- fields-problem
  "The :error of the single-valued `fields` of a redemption at the
  `endpoint`, :token or :authorization, before the code is taken, or nil."
  [fields endpoint]
  (let [{:strs [grant_type code client_id redirect_uri]} fields
        repeated (some (fn [[k v]] (when (= ::ring/repeated v) k)) fields)]
    (cond
      repeated
      (grant-error "invalid_request" (str repeated " is repeated"))

      ;; the authorization endpoint takes the redemptions of older clients,
      ;; which have no grant_type
      (and (nil? grant_type) (= :token endpoint))
      (grant-error "invalid_request" "grant_type is missing")

      (not (contains? #{nil "authorization_code"} grant_type))
      (grant-error "unsupported_grant_type" "grant_type must be authorization_code")

      (some empty? [code client_id redirect_uri])
      (grant-error "invalid_request" "code, client_id and redirect_uri are needed"))))

(defn- redeem!
  "The entry of the code that the single-valued `fields` redeem at the
  `endpoint`, :token or :authorization, taken from the :codes store of
  `opts`, or the :error. A code is taken before it's checked, so that it
  works once, even with a wrong verifier."
  [fields endpoint {:keys [codes now-fn] :as opts}]
  (if-let [error (fields-problem fields endpoint)]
    (async/then nil (constantly error))
    (async/then ((:take! codes) (hash-key (get fields "code")))
                (fn [entry]
                  (if-let [problem (entry-problem entry fields (now-fn))]
                    (grant-error "invalid_grant" problem)
                    {:entry entry})))))

;; IndieAuth 5.3.2
(defn- profile-answer
  "The answer to the redemption of the code of `entry` for the profile URL
  alone."
  [{:keys [me profile] :as entry}]
  (cond-> {:me me}
    profile (assoc :profile profile)))

;; IndieAuth 5.3.3; RFC 6750
(defn- issue-token!
  "Issue an access token for the code of `entry`, kept in the :tokens store
  of `opts`, and give the answer of the token endpoint. A code without a
  scope gives the profile URL alone, as section 5.3.3 says."
  [{:keys [me client-id scopes] :as entry}
   {:keys [tokens token-seconds now-fn] :as opts}]
  (if (empty? scopes)
    (profile-answer entry)
    (let [token   (indieauth/token)
          at      (now-fn)
          scope   (indieauth/scope-text scopes)
          info    (cond-> {:me        me
                           :client-id client-id
                           :scope     scope
                           :issued-at at}
                    token-seconds (assoc :expires (later at token-seconds)))]
      (async/then ((:put! tokens) (hash-key token) info)
                  (fn [_]
                    (cond-> (assoc (profile-answer entry)
                                   :access_token token
                                   :token_type   "Bearer"
                                   :scope        scope)
                      token-seconds (assoc :expires_in token-seconds)))))))

(defn- error-response
  "The Ring response of an OAuth 2.0 `error`, a map of the :code and the
  :reason, by the :cors? of `opts`."
  [{:keys [code reason] :as error} {:keys [cors?] :as opts}]
  (cond-> (ring/json-response 400 {:error code :error_description reason})
    cors? ring/with-cors))

(defn- json-answer
  "The Ring response of 200 with the JSON of `x`, by the :cors? of `opts`."
  [x {:keys [cors?] :as opts}]
  (cond-> (ring/json-response 200 x)
    cors? ring/with-cors))

(defn- redemption-response
  "The Ring response to the POST `request` that redeems a code at the
  `endpoint`, :token or :authorization, by `opts`."
  [request endpoint {:keys [max-form-bytes] :as opts}]
  (if-let [pairs (ring/form-fields request max-form-bytes)]
    (async/then (redeem! (ring/single-values pairs) endpoint opts)
                (fn [{:keys [error entry]}]
                  (cond
                    error                     (error-response error opts)
                    (= :authorization endpoint) (json-answer (profile-answer entry) opts)
                    :else                     (async/then (issue-token! entry opts)
                                                          #(json-answer % opts)))))
    (assoc (error-response {:code "invalid_request" :reason "The form is too large"} opts)
           :status 413)))

;;; the endpoints

(def page-headers
  "The headers of the pages of the authorization endpoint, which no other
  site can frame (RFC 9700, section 4.16), and which tell no other site
  their URL. Add them to your sign-in and consent pages too."
  {"X-Frame-Options"         "DENY"
   "Content-Security-Policy" "frame-ancestors 'none'"
   "Referrer-Policy"         "no-referrer"})

(defn- page
  "The Ring `response` of a page of the authorization endpoint, with
  page-headers unless it has its own."
  [response]
  (update response :headers #(merge page-headers %)))

(defn- error-page
  "The Ring response that tells the user of the `error` of an authorization
  request, by the :error-page of `opts`, a function of the Ring request and
  the error, or else in plain text."
  [request {:keys [reason] :as error} {:keys [error-page] :as opts}]
  (if error-page
    (error-page request error)
    (ring/text-response 400 (str "The authorization request failed: " reason))))

(defn- authorization-page
  "The answer to the GET `ring-request` of a client's authorization
  request, by `opts`."
  [ring-request {:keys [authorize] :as opts}]
  (async/then (authorization-request! (ring/query-fields ring-request) opts)
              (fn [{:keys [request error]}]
                (cond
                  (:redirect error) {:status  302
                                     :headers {"Location" (:redirect error)}
                                     :body    ""}
                  error             (error-page ring-request error opts)
                  :else             (authorize ring-request request)))))

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
  - :authorization-endpoint and :token-endpoint, their URLs
  - :secret, a text of 32 bytes or more, e.g. a token, that signs the
    requests and consents of request-token and consent
  - :codes and :tokens, the stores of codes and of access tokens, e.g.
    memory-store
  - :authorize and :error-page, as above"
  [opts]
  (let [{:keys [authorize] :as opts} (options opts)]
    (when-not (fn? authorize)
      (throw (ex-info "The authorization endpoint needs an :authorize function" {})))
    (ring/handler
     (fn [{:keys [request-method] :as request}]
       (case request-method
         :get     (async/then (authorization-page request (assoc opts :authorize authorize))
                              page)
         :post    (redemption-response request :authorization opts)
         :options (ring/with-cors (ring/text-response 204 ""))
         (ring/not-allowed ["GET" "POST" "OPTIONS"]))))))

;; IndieAuth 4.1.1; RFC 8414, section 2
(defn metadata
  "The metadata document of the server of the `opts` of handler, as a map
  of its JSON.

  The :metadata-url of `opts` is the URL where you serve it, the
  well-known URL of RFC 8414 by default. The issuer must be a prefix of
  it, as section 3.1 says, or it throws. The :service-documentation of
  `opts`, a URL, is listed too when it's given."
  [opts]
  (let [{:keys [issuer authorization-endpoint token-endpoint metadata-url
                scopes-supported service-documentation]}
        (options opts)
        metadata-url (or metadata-url (indieauth/well-known-url issuer))]
    (when-not (indieauth/issuer-of? issuer metadata-url)
      (throw (ex-info "The :issuer isn't a prefix of the :metadata-url"
                      {:issuer issuer :metadata-url metadata-url})))
    (cond-> {:issuer                                         issuer
             :authorization_endpoint                         authorization-endpoint
             :scopes_supported                               (vec scopes-supported)
             :response_types_supported                       ["code"]
             :grant_types_supported                          ["authorization_code"]
             :code_challenge_methods_supported               ["S256"]
             :authorization_response_iss_parameter_supported true}
      token-endpoint        (assoc :token_endpoint token-endpoint)
      service-documentation (assoc :service_documentation service-documentation))))

(defn metadata-handler
  "A Ring handler that serves the metadata document of the server of the
  `opts` of handler, which a page in any browser can read, by :cors?."
  [opts]
  (let [{:keys [cors?] :as opts} (options opts)
        body                     (json/write-json (metadata opts))]
    (ring/handler
     (fn [{:keys [request-method] :as request}]
       (case request-method
         (:get :head) (cond-> (ring/response 200 "application/json" body)
                        cors? ring/with-cors)
         :options     (ring/with-cors (ring/text-response 204 ""))
         (ring/not-allowed ["GET" "HEAD" "OPTIONS"]))))))

;; IndieAuth 4.1
(defn links
  "The links that name the server of the `opts` of handler on a profile
  page, as maps of :rel and :href, e.g. for the link elements in its head:
  indieauth-metadata, and authorization_endpoint and token_endpoint for
  older clients."
  [opts]
  (let [{:keys [issuer authorization-endpoint token-endpoint metadata-url]}
        (options opts)]
    (cond-> [{:rel "indieauth-metadata" :href (or metadata-url
                                                  (indieauth/well-known-url issuer))}
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
    (let [card  (representative-card (mf/parse body url) url)
          email (some-> (property card :email) (str/replace #"(?i)^mailto:" ""))]
      (not-empty
       (into {}
             (filter (fn [[_ v]] (and (string? v) (seq v))))
             {:name  (property card :name)
              :url   (property card :url)
              :photo (property card :photo)
              :email email})))))

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
                 (fn [{:keys [value]}]
                   (when (and value (<= 200 (:status value) 299))
                     (profile value)))))))

;;; resource servers

;; RFC 6750, sections 2.1 and 2.2
(defn bearer-token
  "The access token of the Ring `request`: that of its Authorization
  header, or else the access_token of its :form-params, as a Micropub
  client can send it. Nil when it has none."
  [request]
  (or (some->> (ring/header request "authorization")
               (re-matches #"(?i)\s*Bearer\s+(\S+)\s*")
               second)
      (let [form (:form-params request)
            v    (get form "access_token" (get form :access_token))]
        (when (and (string? v) (seq v))
          v))))

;; IndieAuth 6 and 8
(defn token-info!
  "What the :tokens store of `opts` keeps of the access `token`: a map of
  the :me, :client-id, :scope, :issued-at and :expires, or nil when the
  token is unknown, revoked or expired. In ClojureScript, it gives a
  promise."
  [token opts]
  (let [{:keys [tokens now-fn]} (merge default-options opts)]
    (async/then (when (and (string? token) (seq token))
                  ((:get tokens) (hash-key token)))
                (fn [info]
                  (when (and info (not (expired? info (now-fn))))
                    info)))))

;; IndieAuth 8.1; RFC 6750, section 3.1
(defn access-problem
  "What keeps the access token of `info`, as token-info! gives it, from a
  request that needs one of the `scopes`, or any scope when they're empty,
  as a map of the :status, the :code and the :reason, or nil."
  [info scopes]
  (let [granted (set (indieauth/scopes (:scope info)))]
    (cond
      (nil? info)
      {:status 401 :code "invalid_token" :reason "The access token is unknown, revoked or expired"}

      (and (seq scopes) (not-any? granted scopes))
      {:status 403
       :code   "insufficient_scope"
       :reason (str "The access token needs one of the scopes " (str/join ", " scopes))
       :scope  (indieauth/scope-text scopes)})))

;; RFC 6750, section 3
(defn problem-response
  "The Ring response of the `problem` of access-problem, with the
  WWW-Authenticate header of a bearer token. A problem without a :code is
  that of a request without a token, whose answer says no more, as
  section 8.1 has it."
  [{:keys [status code reason scope] :as problem}]
  (let [challenge (str "Bearer"
                       (when code (str " error=\"" code "\""))
                       (when scope (str ", scope=\"" scope "\"")))]
    (-> (if code
          (ring/json-response status {:error code :error_description reason})
          (ring/text-response status ""))
        (assoc-in [:headers "WWW-Authenticate"] challenge))))

(defn access!
  "What the :tokens store of `opts` keeps of the access token of the Ring
  `request`, if it grants one of the `scopes`, or any scope when they're
  empty, as token-info! gives it. Else a map of the :error, as
  access-problem gives it, and the Ring :response to answer with. In
  ClojureScript, it gives a promise.

  A resource server in the same process as the token endpoint checks a
  token this way, e.g. a Micropub endpoint. Whether the token's :me may
  use the resource is yours to say."
  [request scopes opts]
  (if-let [token (bearer-token request)]
    (async/then (token-info! token opts)
                (fn [info]
                  (if-let [problem (access-problem info scopes)]
                    {:error problem :response (problem-response problem)}
                    info)))
    (let [problem {:status 401 :reason "The request has no access token"}]
      (async/then nil (constantly {:error    problem
                                   :response (problem-response problem)})))))

(defn token-handler
  "A Ring handler for the token endpoint, by the `opts` of handler.

  A POST redeems a code for an access token, whose hash goes to the :put!
  of the :tokens store. The JSON of the answer has :access_token,
  :token_type Bearer, :scope and :me, :profile when the user granted it,
  and :expires_in with :token-seconds. A code without a scope gives the
  :me alone, as section 5.3.3 says. No cache keeps an answer."
  [opts]
  (let [opts (options opts)]
    (ring/handler
     (fn [{:keys [request-method] :as request}]
       (case request-method
         :post    (redemption-response request :token opts)
         :options (ring/with-cors (ring/text-response 204 ""))
         (ring/not-allowed ["POST" "OPTIONS"]))))))
