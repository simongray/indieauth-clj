(ns dk.simongray.indieauth.resource
  "The checks of an access token that a resource server makes, e.g. a
  Micropub endpoint: in the store of tokens of a server in the same
  process, or at the introspection endpoint of one in another.

  The code follows sections 6 and 8 of the IndieAuth Living Standard of 11
  July 2024, https://indieauth.spec.indieweb.org/, and RFC 6750."
  (:require [clojure.string :as str]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

(def default-options
  "The default of each option of a resource server that has one:

  - :timeout-seconds, 10, and :max-json-bytes, 256 kB: the limits of a
    request to an introspection endpoint
  - :send, http/send-public!, which sends to the public internet alone
  - :now-fn, a function that gives the instant now"
  {:timeout-seconds 10
   :max-json-bytes  (* 256 1024)
   :send            http/send-public!
   :now-fn          instant/now})

;; RFC 6750, section 2.1
(defn header-token
  "The bearer token of the Authorization header of the Ring `request`, or
  nil."
  [request]
  (some->> (ring/header request "authorization")
           (re-matches #"(?i)\s*Bearer\s+(\S+)\s*")
           second))

;; RFC 6750, sections 2.1 and 2.2
(defn bearer-token
  "The access token of the Ring `request`: that of its Authorization
  header, or else the access_token of its :form-params, as a Micropub
  client can send it. Nil when it has none."
  [request]
  (or (header-token request)
      (let [form (:form-params request)
            v    (get form "access_token" (get form :access_token))]
        (when (and (string? v) (seq v))
          v))))

;; IndieAuth 6 and 8
(defn token-info!
  "What the :tokens store of `opts` keeps of the access `token`: a map of
  the :me, :client-id, :scope, :issued-at and :expires, and the id of its
  :grant, or nil when the token is unknown, revoked or expired. A refresh
  token is no access token. In ClojureScript, it gives a promise."
  [token opts]
  (let [{:keys [tokens now-fn]} (merge default-options opts)]
    (async/then (when (and (string? token) (seq token))
                  ((:get tokens) (digest/text token)))
                (fn [info]
                  (when (and (= :access (:type info))
                             (not (instant/expired? info (now-fn))))
                    (dissoc info :type))))))

(defn- seconds-of
  "The number `x`, or the number that the text `x` writes, as the example
  of section 6.2 writes them, or nil."
  [x]
  (cond
    (int? x)    x
    (string? x) (parse-long x)))

;; IndieAuth 6.2; RFC 7662, section 2.2
(defn- introspected
  "The token information of the answer `m` of an introspection endpoint,
  or nil for a token that isn't active, or an answer without a me."
  [{:keys [active me client_id scope exp iat] :as m}]
  (when (and (contains? #{true "true"} active) (string? me))
    (cond-> {:me me :client-id client_id :scope scope}
      (seconds-of iat) (assoc :issued-at (instant/of-ms (* 1000 (seconds-of iat))))
      (seconds-of exp) (assoc :expires (instant/of-ms (* 1000 (seconds-of exp)))))))

;; IndieAuth 6.1; RFC 7662, section 2.1
(defn introspect!
  "Ask the :introspection-endpoint of `opts` about the access `token`, with
  the :resource-token of `opts`, and give what it says as token-info!
  does, nil for a token that isn't active, or a map of the :error when it
  can't be asked. In ClojureScript, it gives a promise.

  A resource server checks the tokens of a server in another process this
  way. The resource token can be a hidden text, and the `opts` are also
  those of http/send!, and :send."
  [token {:keys [introspection-endpoint resource-token] :as opts}]
  (let [{:keys [send max-json-bytes] :as opts} (merge default-options opts)
        request {:method  :post
                 :url     introspection-endpoint
                 :headers {"Content-Type"  "application/x-www-form-urlencoded"
                           "Accept"        "application/json"
                           "Authorization" (http/authorization {:token resource-token})}
                 :body    (secret/hide (url/query-string [["token" token]]))}]
    (async/then (http/try-send! send request (assoc opts
                                                    :max-bytes max-json-bytes
                                                    :max-redirects 0))
                (fn [{{:keys [status body]} :value error :error}]
                  (let [m (json/read-object body)]
                    (cond
                      error
                      {:error (http/failure error)}

                      (not (ring/success? status))
                      {:error {:reason (str "The introspection endpoint answered " status)
                               :status status}}

                      (nil? m)
                      {:error {:reason "The introspection endpoint's answer isn't JSON"}}

                      :else
                      (introspected m)))))))

;; IndieAuth 8.1; RFC 6750, section 3.1
(defn access-problem
  "Why the access token of `info`, as token-info! gives it, can't be used
  for a request that needs one of the `scopes`, or any scope when they're
  empty, as a map of the :status, the :code and the :reason, or nil when
  it can."
  [info scopes]
  (cond
    (nil? info)
    {:status 401 :code "invalid_token" :reason "The access token is unknown, revoked or expired"}

    (and (seq scopes) (not-any? (set (indieauth/scopes (:scope info))) scopes))
    {:status 403
     :code   "insufficient_scope"
     :reason (str "The access token needs one of the scopes " (str/join ", " scopes))
     :scope  (indieauth/scope-text scopes)}))

;; RFC 6750, section 3
(defn problem-response
  "The Ring response of the `problem` of access-problem, with the
  WWW-Authenticate header of a bearer token for a status of 401 or 403. A
  problem without a :code is that of a request without a token, whose
  answer says no more, as section 8.1 has it."
  [{:keys [status code reason scope] :as problem}]
  (let [challenge (str "Bearer"
                       (when code (str " error=\"" code "\""))
                       (when scope (str ", scope=\"" scope "\"")))]
    (cond-> (if code
              (ring/json-response status {:error code :error_description reason})
              (ring/text-response status ""))
      (#{401 403} status) (assoc-in [:headers "WWW-Authenticate"] challenge))))

(defn- refusal
  "The map of the :error `problem` and its Ring :response."
  [problem]
  {:error problem :response (problem-response problem)})

(defn access!
  "What the server keeps of the access token of the Ring `request`, if it
  grants one of the `scopes`, or any scope when they're empty, as
  token-info! gives it. Else a map of the :error, as access-problem gives
  it, and the Ring :response to answer with. In ClojureScript, it gives a
  promise.

  In the server's own process, give its :tokens store in `opts`, and else
  the :introspection-endpoint and :resource-token of introspect!. Whether
  the token's :me may use the resource is up to you."
  [request scopes {:keys [tokens] :as opts}]
  (if-let [token (bearer-token request)]
    (async/then (if tokens
                  (token-info! token opts)
                  (introspect! token opts))
                (fn [info]
                  (if (:error info)
                    (refusal {:status 503 :reason "The access token couldn't be checked"})
                    (if-let [problem (access-problem info scopes)]
                      (refusal problem)
                      info))))
    (async/then (refusal {:status 401 :reason "The request has no access token"})
                identity)))
