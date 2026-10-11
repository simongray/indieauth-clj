(ns ^:no-doc dk.simongray.indieauth.grant
  "Codes, grants and tokens in the stores of a server: what a user grants,
  the redemption of a code, the refresh of a token and its revocation.

  A grant is what a user granted a client with a code. Its access and
  refresh tokens belong to it, so that revoking it revokes them all. The
  store of tokens keeps it under a key of its own, with the keys of its
  tokens and when each expires."
  (:require [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.wary-fetch.async :as async]))

(defn- each!
  "Call `f` on each of `xs` in turn, after what the call before gives, a
  value, a future or a promise, is there."
  [f xs]
  (reduce (fn [acc x] (async/then acc (fn [_] (f x)))) nil xs))

(defn grant-key
  "The key of the grant `id` in a store of tokens, which no hash can be."
  [id]
  (str "grant:" id))

(defn- latest
  "The latest of the instants `xs`, or nil when one of them is nil, which
  is never."
  [xs]
  (when (every? some? xs)
    (apply max-key inst-ms xs)))

;;; what the user grants

(defn granted-scopes
  "The scopes of the `request` that the user grants, among `scopes`, all
  of them when nil. The email scope goes with the profile scope alone."
  [request scopes]
  (let [asked  (:scopes request)
        chosen (if (nil? scopes) asked (filterv (set scopes) asked))]
    (if (some #{"profile"} chosen)
      (vec chosen)
      (filterv #(not= "email" %) chosen))))

;; IndieAuth 5.3.4
(defn granted-profile
  "The `profile` information of the user that the `scopes` grant: the
  :name, :url and :photo with profile, and the :email with email too."
  [profile scopes]
  (when (and (map? profile) (some #{"profile"} scopes))
    (not-empty
     (into {}
           (filter (fn [[_ v]] (and (string? v) (seq v))))
           (select-keys profile (cond-> [:name :url :photo]
                                  (some #{"email"} scopes) (conj :email)))))))

;;; tokens

(defn- revoke-grant!
  "Delete the grant `id`, and each of its tokens, from the :tokens store of
  `opts`."
  [id {:keys [tokens] :as opts}]
  (async/then ((:get tokens) (grant-key id))
              (fn [grant]
                (each! (:delete! tokens) (conj (vec (keys (:tokens grant))) (grant-key id))))))

;; IndieAuth 5.3.2
(defn profile-answer
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

;;; redemption

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
(defn redeem-code!
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

(defn used!
  "Keep in the :codes store of `opts` that the code of key `k` and `entry`
  was used, with the `grant` id of its tokens, if any, until it would have
  expired."
  [k entry grant {:keys [codes] :as opts}]
  ((:put! codes) k (cond-> {:used? true :expires (:expires entry)}
                     grant (assoc :grant grant))))

(defn code-answer!
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

;;; refresh and revocation

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
(defn refresh-answer!
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
(defn revoke!
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
