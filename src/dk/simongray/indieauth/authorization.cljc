(ns ^:no-doc dk.simongray.indieauth.authorization
  "The checks of a client's authorization request at the authorization
  endpoint, and the URL that sends the browser back to the client with an
  error."
  (:require [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.identifier :as identifier]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.wary-fetch.url :as url]))

(def unsafe-schemes
  "The schemes of URLs that are never a redirect URL, since a browser runs
  them or shows a local file."
  #{"javascript" "data" "vbscript" "file" "blob"})

(defn repeated-field
  "The name of a field that comes more than once in the single-valued
  `fields`, or nil."
  [fields]
  (some (fn [[k v]] (when (= ::ring/repeated v) k)) fields))

;; RFC 6749, section 4.1.2.1; RFC 9207, section 2
(defn error-redirect
  "The URL that sends the browser back to the `redirect-uri` of a client
  with the error `code` and `description`, the `state` and the `issuer`."
  [redirect-uri state issuer code description]
  (url/with-query redirect-uri [["error" code]
                                ["error_description" description]
                                ["state" state]
                                ["iss" issuer]]))

(defn- redirect-uri-problem
  "What's wrong with `s` as a redirect URL, or nil."
  [s]
  (let [{:keys [scheme fragment]} (url/parts s)]
    (cond
      (nil? scheme)                             "redirect_uri isn't an absolute URL"
      (some? fragment)                          "redirect_uri has a fragment"
      (contains? unsafe-schemes scheme)         "redirect_uri has a scheme that isn't allowed"
      (re-find identifier/unsafe-characters s)  "redirect_uri has a space or a backslash"
      (and (#{"http" "https"} scheme)
           (not (url/web-url? s)))              "redirect_uri has no host")))

(defn client-problem
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

;; IndieAuth 5.2; RFC 7636, section 4.3
(defn- pkce-problem
  "What's wrong with the PKCE `challenge` and `method` of a request, or
  nil. Only S256 is taken, and a request without PKCE isn't."
  [challenge method]
  (cond
    (nil? challenge)                                  "code_challenge is missing"
    (not= "S256" method)                              "code_challenge_method must be S256"
    (not (re-matches #"[A-Za-z0-9_-]{43}" challenge)) "code_challenge isn't an S256 challenge"))

(defn request-error
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
