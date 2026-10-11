(ns ^:no-doc dk.simongray.indieauth.endpoint
  "The answers of a server's endpoints to the forms that clients and
  resource servers post, as Ring responses: the redemption of a code, the
  token endpoint's grants, revocation and introspection."
  (:require [dk.simongray.indieauth.authorization :as authorization]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.grant :as grant]
            [dk.simongray.indieauth.instant :as instant]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.secret :as secret]))

(defn error-response
  "The Ring response of an OAuth 2.0 `error`, a map of the :code and the
  :reason, by the :cors? of `opts`."
  [{:keys [code reason] :as error} {:keys [cors?] :as opts}]
  (ring/with-cors (ring/json-response 400 {:error code :error_description reason}) cors?))

(defn json-answer
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

(defn form-response
  "The Ring response to the POST `request` of a form, which `f`, a function
  of its single-valued fields, answers, by the :max-form-bytes of `opts`."
  [request f {:keys [max-form-bytes] :as opts}]
  (if-let [pairs (ring/form-fields request max-form-bytes)]
    (let [fields (ring/single-values pairs)]
      (if-let [repeated (authorization/repeated-field fields)]
        (error-response {:code "invalid_request" :reason (str repeated " is repeated")} opts)
        (f fields)))
    (assoc (error-response {:code "invalid_request" :reason "The form is too large"} opts)
           :status 413)))

;; IndieAuth 5.3.2
(defn profile-response
  "The Ring response of the authorization endpoint to the redemption of a
  code with the single-valued `fields`, by `opts`. The redemptions of older
  clients have no grant_type."
  [fields opts]
  (if (contains? #{nil "authorization_code"} (get fields "grant_type"))
    (async/then (grant/redeem-code! fields opts)
                (fn [{:keys [error key entry] :as redeemed}]
                  (if error
                    (error-response error opts)
                    (async/then (grant/used! key entry nil opts)
                                (fn [_] (json-answer (grant/profile-answer entry) opts))))))
    (error-response {:code "unsupported_grant_type" :reason "grant_type must be authorization_code"}
                    opts)))

(defn revoked-response
  "The Ring response to the revocation of the `token`, by `opts`: 200
  whether it was known or not, as RFC 7009, section 2.2, says."
  [token {:keys [cors?] :as opts}]
  (if (and (string? token) (seq token))
    (async/then (grant/revoke! token opts)
                (fn [_] (ring/with-cors (ring/text-response 200 "") cors?)))
    (error-response {:code "invalid_request" :reason "token is missing"} opts)))

;; IndieAuth 5.3.3, 5.5.1 and 7
(defn token-response
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
      (async/then (grant/redeem-code! fields opts)
                  (fn [{:keys [error] :as redeemed}]
                    (if error
                      (error-response error opts)
                      (async/then (grant/code-answer! redeemed opts) #(answered % opts)))))

      (and refresh-seconds (= "refresh_token" grant_type))
      (async/then (grant/refresh-answer! fields opts) #(answered % opts))

      :else
      (error-response {:code   "unsupported_grant_type"
                       :reason (str "grant_type must be authorization_code"
                                    (when refresh-seconds " or refresh_token"))}
                      opts))))

;; The W3C Note of IndieAuth of 23 January 2018, section 6.3.4
(defn legacy-verification
  "The answer of the token endpoint to an older resource server's GET
  `request`, which verifies the bearer token of its Authorization header,
  by `opts`."
  [request opts]
  (async/then (resource/access! request [] opts)
              (fn [{:keys [error response me client-id scope]}]
                (if error
                  response
                  (ring/json-response 200 {:me me :client_id client-id :scope scope})))))

(defn resource-pred
  "A function of a Ring request that says whether it has a bearer token
  among the `resource-tokens`, by their hashes, compared in a time that
  doesn't tell where they differ."
  [resource-tokens]
  (let [hashes (mapv #(bytes/hash-text (str (secret/reveal %))) resource-tokens)]
    (fn [request]
      (when-let [given (some-> (resource/header-token request) bytes/hash-text)]
        (boolean (some #(bytes/same-text? given %) hashes))))))

;; IndieAuth 6.2; RFC 7662, section 2.2
(defn introspection
  "The answer of the introspection endpoint for the token information
  `info`."
  [{:keys [me client-id scope issued-at expires] :as info}]
  (cond-> {:active    true
           :me        me
           :client_id client-id
           :scope     scope
           :iat       (instant/epoch-seconds issued-at)}
    expires (assoc :exp (instant/epoch-seconds expires))))
