(ns dk.simongray.indieauth-test
  "IndieAuth for clients: the identifiers, discovery, the authorization
  request, the callback and the redemption. A case of indieauth.rocks's
  client tests is named by its number, and a server of its own misbehaves
  on purpose, as the suite's does."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]))

(deftest profile-urls
  (testing "section 3.2, the valid examples"
    (doseq [s ["https://example.com/" "https://example.com/username" "https://example.com/users?id=100"]]
      (is (indieauth/profile-url? s) s)))
  (testing "section 3.2, the invalid examples"
    (doseq [s ["example.com" "mailto:user@example.com" "https://example.com/foo/../bar" "https://example.com/#me"
               "https://user:pass@example.com/" "https://example.com:8443/" "https://172.28.92.51/"]]
      (is (not (indieauth/profile-url? s)) s)))
  (testing "what a browser would read differently"
    (doseq [s ["https://example.com/a/%2E%2e/b" "https://[::1]/" "https://0x7f.1/" "https://a.example\\@b.example/"
               "https://a b.example/" "https://example.com/#" "https:///x" nil]]
      (is (not (indieauth/profile-url? s)) (pr-str s))))
  (is (indieauth/profile-url? "https://example.com") "an empty path is /, as section 3.4 has it"))

(deftest client-ids
  (testing "section 3.3"
    (doseq [s ["https://app.example.com/" "https://app.example.com:8443/app" "http://127.0.0.1:8080/" "http://[::1]/" "http://localhost:3000/"]]
      (is (indieauth/client-id? s) s))
    (doseq [s ["https://10.0.0.1/" "https://app.example.com/#x" "https://u@app.example.com/" "https://app.example.com/a/./b"
               "https://app.example.com:99999/" "app.example.com"]]
      (is (not (indieauth/client-id? s)) s))))

(deftest issuers
  (testing "section 3.1"
    (is (indieauth/issuer? "https://example.com/"))
    (is (indieauth/issuer? "https://example.com/wp-json/indieauth/1.0"))
    (doseq [s ["http://example.com/" "https://example.com/?a" "https://example.com/#" nil 42]]
      (is (not (indieauth/issuer? s)) (pr-str s))))
  (testing "a prefix of the URL of the metadata"
    (is (indieauth/issuer-of? "https://example.com/" "https://example.com/.well-known/oauth-authorization-server"))
    (is (indieauth/issuer-of? "https://example.com/wp-json/indieauth/1.0" "https://example.com/wp-json/indieauth/1.0/metadata"))
    (is (not (indieauth/issuer-of? "https://example.com" "https://example.com.evil/meta")) "that ends where a segment ends")
    (is (not (indieauth/issuer-of? "https://example.com/wp" "https://example.com/wpx/meta"))))
  (testing "RFC 8414, section 3.1: or its well-known URL"
    (is (= "https://example.com/.well-known/oauth-authorization-server/issuer1"
           (indieauth/well-known-url "https://example.com/issuer1/")))
    (is (indieauth/issuer-of? "https://example.com/issuer1" "https://example.com/.well-known/oauth-authorization-server/issuer1"))))

(deftest canonical-urls
  (testing "section 3.4"
    (is (= "https://example.com/" (indieauth/canonical-url "https://example.com")))
    (is (= "https://example.com/" (indieauth/canonical-url "HTTPS://Example.COM")))
    (is (= "https://example.com/" (indieauth/canonical-url "example.com")) "C111: a host alone")
    (is (= "http://example.com/" (indieauth/canonical-url "http://example.com:80")) "without a default port"))
  (testing "nothing else changes"
    (is (= "https://example.com/Me/" (indieauth/canonical-url "https://example.com/Me/")))
    (is (= "https://example.com:8443/?a#b" (indieauth/canonical-url " example.com:8443?a#b "))))
  (is (nil? (indieauth/canonical-url "mailto:user@example.com")))
  (is (nil? (indieauth/canonical-url ""))))

(deftest pkce-and-scopes
  (testing "RFC 7636, appendix B"
    (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
           (indieauth/code-challenge "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))))
  (is (indieauth/code-verifier? (indieauth/code-verifier)))
  (is (not= (indieauth/code-verifier) (indieauth/code-verifier)))
  (is (not (indieauth/code-verifier? "too-short")))
  (is (= ["profile" "create"] (indieauth/scopes " profile  create profile")))
  (is (= [] (indieauth/scopes nil)))
  (is (nil? (indieauth/scopes "a\"b")) "RFC 6749, section 3.3")
  (is (indieauth/token-scope? ["profile" "create"]))
  (is (not (indieauth/token-scope? ["profile" "email"]))))

;; the test server

(def metadata
  {:issuer                                         "https://auth.example/"
   :authorization_endpoint                         "https://auth.example/auth"
   :token_endpoint                                 "https://tokens.example/token"
   :code_challenge_methods_supported               ["S256"]
   :authorization_response_iss_parameter_supported true})

(def metadata-url "https://auth.example/.well-known/oauth-authorization-server")

(def decoy
  {:issuer                 "https://decoy.example/"
   :authorization_endpoint "https://decoy.example/auth"
   :token_endpoint         "https://decoy.example/token"})

(defn- metadata-link
  "A link element to the metadata at `href`."
  ([href]
   (metadata-link "indieauth-metadata" href))
  ([rel href]
   (str "<link rel=\"" rel "\" href=\"" href "\">")))

(def pages
  "The profile pages of the test server, each by its URL."
  {"https://user.example/c101" (t/page (metadata-link metadata-url))
   "https://user.example/c102" (t/page "<p>Hi" (str "<" metadata-url ">; rel=\"indieauth-metadata\""))
   "https://user.example/c103" (t/page (metadata-link "https://decoy.example/metadata")
                                       (str "<" metadata-url ">; rel=\"indieauth-metadata\""))
   "https://user.example/c104" (t/page (str (metadata-link metadata-url) (metadata-link "https://decoy.example/metadata")))
   "https://user.example/c105/page" (t/page (metadata-link "meta"))
   "https://user.example/c106" (t/redirect 301 "/c106/moved")
   "https://user.example/c106/moved" (t/redirect 302 "https://www.user.example/c106/")
   "https://www.user.example/c106/" (t/page (metadata-link "/.well-known/oauth-authorization-server"))
   "https://user.example/c107" (t/page (metadata-link "me indieauth-metadata" metadata-url))
   "https://user.example/c108" (t/page (str (metadata-link "authorization_endpoint" "https://auth.example/auth")
                                            (metadata-link "token_endpoint" "https://tokens.example/token")))
   "https://user.example/c109" (t/page (str (metadata-link "authorization_endpoint" "https://decoy.example/auth")
                                            (metadata-link metadata-url)))
   "https://user.example/c110" (t/page (metadata-link "https://other.example/meta"))
   "https://user.example/" (t/page (metadata-link metadata-url))
   "https://user.example/c112" (t/page (str "<html><head>" (metadata-link metadata-url) "</head>"
                                            "<body><p>A comment" (metadata-link "https://decoy.example/metadata")))
   "https://user.example/none" (t/page "<p>No server")
   "https://user.example/bad-metadata" (t/page (metadata-link "https://elsewhere.example/meta"))
   "https://user.example/gone" (constantly {:status 410 :headers {} :body ""})
   "https://user.example/c402" (t/page (metadata-link metadata-url))
   "https://another.example/" (t/page (metadata-link metadata-url))
   "https://another.example/other-server" (t/page (metadata-link "https://decoy.example/metadata"))})

(def documents
  "The metadata documents of the test server, each by its URL."
  {metadata-url                                     (t/json-doc metadata)
   "https://user.example/c105/meta"                 (t/json-doc (assoc metadata :issuer "https://user.example/c105/"))
   "https://www.user.example/.well-known/oauth-authorization-server"
   (t/json-doc (assoc metadata :issuer "https://www.user.example/"))
   "https://other.example/meta"                     (t/json-doc (assoc metadata
                                                                       :issuer "https://other.example/"
                                                                       :token_endpoint "https://tokens.example/other"
                                                                       :introspection_endpoint "https://tokens.example/introspect"
                                                                       :future_field {:a 1}))
   "https://decoy.example/metadata"                 (t/json-doc decoy)
   "https://elsewhere.example/meta"                 (t/json-doc metadata)})

(defn- world
  "The options of a client in the test world of `routes` over pages and
  documents, which logs each request to the atom `log`."
  ([log]
   (world log {}))
  ([log routes]
   {:send (t/network (merge pages documents routes) log)}))

(defn- discovered
  "A step that discovers the server of `url` and calls `f` with it and the
  URLs of the requests it took."
  [url f]
  (fn []
    (let [log (atom [])]
      (async/then (indieauth/discover! url (world log))
                  #(f % (mapv :url @log))))))

(defn- decoy-free?
  "Whether no request in `urls` went to the decoy server."
  [urls]
  (not-any? #(str/includes? % "decoy.example") urls))

(deftest server-discovery
  (run
   (discovered "https://user.example/c101"
               (fn [d urls]
                 (testing "C101: from an HTML link"
                   (is (= {:me                     "https://user.example/c101"
                           :urls                   ["https://user.example/c101"]
                           :metadata-url           metadata-url
                           :metadata               metadata
                           :issuer                 "https://auth.example/"
                           :authorization-endpoint "https://auth.example/auth"
                           :token-endpoint         "https://tokens.example/token"}
                          d))
                   (is (= ["https://user.example/c101" metadata-url] urls)))))
   (discovered "https://user.example/c102"
               (fn [d _]
                 (testing "C102: from a Link header"
                   (is (= metadata-url (:metadata-url d))))))
   (discovered "https://user.example/c103"
               (fn [d urls]
                 (testing "C103: the Link header before the HTML"
                   (is (= "https://auth.example/auth" (:authorization-endpoint d)))
                   (is (decoy-free? urls)))))
   (discovered "https://user.example/c104"
               (fn [d urls]
                 (testing "C104: the first HTML link"
                   (is (= "https://auth.example/auth" (:authorization-endpoint d)))
                   (is (decoy-free? urls)))))
   (discovered "https://user.example/c105/page"
               (fn [d _]
                 (testing "C105: a relative metadata URL"
                   (is (= "https://user.example/c105/meta" (:metadata-url d))))))
   (discovered "https://user.example/c106"
               (fn [d _]
                 (testing "C106: after redirects, against the last URL"
                   (is (= "https://www.user.example/.well-known/oauth-authorization-server" (:metadata-url d)))
                   (is (= ["https://user.example/c106" "https://user.example/c106/moved" "https://www.user.example/c106/"]
                          (:urls d))))))
   (discovered "https://user.example/c107"
               (fn [d _]
                 (testing "C107: one of several rel values"
                   (is (= metadata-url (:metadata-url d))))))
   (discovered "https://user.example/c108"
               (fn [d _]
                 (testing "C108: the older links"
                   (is (= {:me                     "https://user.example/c108"
                           :urls                   ["https://user.example/c108"]
                           :authorization-endpoint "https://auth.example/auth"
                           :token-endpoint         "https://tokens.example/token"}
                          d)))))
   (discovered "https://user.example/c109"
               (fn [d urls]
                 (testing "C109: the metadata before the older links"
                   (is (= "https://auth.example/auth" (:authorization-endpoint d)))
                   (is (decoy-free? urls)))))
   (discovered "https://user.example/c110"
               (fn [d _]
                 (testing "C110: a token endpoint on another host, and fields it doesn't know"
                   (is (= "https://tokens.example/other" (:token-endpoint d))))))
   (discovered "user.example"
               (fn [d _]
                 (testing "C111: a URL typed without a scheme"
                   (is (= "https://user.example/" (:me d)))
                   (is (= "https://auth.example/auth" (:authorization-endpoint d))))))
   (discovered "https://user.example/c112"
               (fn [d urls]
                 (testing "C112: not a link in the body"
                   (is (= "https://auth.example/auth" (:authorization-endpoint d)))
                   (is (decoy-free? urls)))))
   (discovered "https://user.example/none"
               (fn [d _]
                 (testing "a page without a server"
                   (is (= ::indieauth/no-server (-> d :error :type))))))
   (discovered "https://user.example/bad-metadata"
               (fn [d _]
                 (testing "metadata whose issuer isn't a prefix of its URL"
                   (is (= ::indieauth/invalid-metadata (-> d :error :type))))))
   (discovered "https://user.example/gone"
               (fn [d _]
                 (testing "a page that fails"
                   (is (= {:type ::indieauth/failed :status 410} (select-keys (:error d) [:type :status]))))))
   (discovered "https://user.example:8443/"
               (fn [d urls]
                 (testing "not a profile URL, which isn't fetched"
                   (is (= ::indieauth/invalid-url (-> d :error :type)))
                   (is (empty? urls)))))))

(deftest public-internet-alone
  (run
   #(async/then (indieauth/discover! "https://localhost/")
                (fn [d]
                  (is (some? (:error d)) "by default, no request goes to the network of the client")))))

(def client
  {:client-id    "https://app.example/"
   :redirect-uri "https://app.example/callback"})

(def discovery
  {:me                     "https://user.example/"
   :urls                   ["https://user.example/"]
   :issuer                 "https://auth.example/"
   :authorization-endpoint "https://auth.example/auth?existing=1"
   :token-endpoint         "https://tokens.example/token"})

(deftest authorization-requests
  (let [{:keys [url session]} (indieauth/authorization-request discovery (assoc client :scope "profile create"))
        params                (t/query url)]
    (testing "C201: an authorization code"
      (is (= "code" (params "response_type")))
      (is (str/starts-with? url "https://auth.example/auth?existing=1&")))
    (testing "C202 and C203: the client"
      (is (= "https://app.example/" (params "client_id")))
      (is (= "https://app.example/callback" (params "redirect_uri"))))
    (testing "C204: a state that nobody can guess"
      (is (= (:state session) (params "state")))
      (is (<= 43 (count (params "state")))))
    (testing "C205: PKCE with S256"
      (is (= "S256" (params "code_challenge_method")))
      (is (= (indieauth/code-challenge (:code-verifier session)) (params "code_challenge")))
      (is (indieauth/code-verifier? (:code-verifier session))))
    (testing "C206: a new challenge each time"
      (is (not= (params "code_challenge")
                (get (t/query (:url (indieauth/authorization-request discovery client))) "code_challenge"))))
    (testing "C207: the me"
      (is (= "https://user.example/" (params "me"))))
    (testing "C210: valid scopes"
      (is (= "profile create" (params "scope")))
      (is (thrown? #?(:clj Exception :cljs :default)
                   (indieauth/authorization-request discovery (assoc client :scope ["email"])))
          "email without profile")
      (is (thrown? #?(:clj Exception :cljs :default)
                   (indieauth/authorization-request discovery (assoc client :scope "a\\b")))))
    (testing "the session"
      (is (= (merge (dissoc discovery :urls) client
                    {:urls  ["https://user.example/"]
                     :scope "profile create"})
             (dissoc session :state :code-verifier)))))
  (testing "no scope, no scope parameter"
    (is (nil? (get (t/query (:url (indieauth/authorization-request discovery client))) "scope"))))
  (testing "an access token needs a token endpoint"
    (is (= ::indieauth/no-token-endpoint
           (-> (indieauth/authorization-request (dissoc discovery :token-endpoint) (assoc client :scope "create"))
               :error :type)))
    (is (:url (indieauth/authorization-request (dissoc discovery :token-endpoint) (assoc client :scope "profile")))))
  (testing "a client that isn't valid"
    (is (thrown? #?(:clj Exception :cljs :default)
                 (indieauth/authorization-request discovery (assoc client :client-id "https://app.example/#x"))))))

(def secret-text "a secret of thirty-two bytes, at least")

(deftest signed-states
  (let [noon                  #inst "2026-10-11T12:00:00Z"
        {:keys [url session]} (indieauth/authorization-request discovery (assoc client
                                                                                :scope "create"
                                                                                :secret secret-text
                                                                                :now-fn (constantly noon)))
        state                 (get (t/query url) "state")]
    (testing "the state carries the session, and the verifier comes from the state"
      (is (= session (indieauth/state-session secret-text state {:now-fn (constantly #inst "2026-10-11T12:09:00Z")})))
      (is (= (indieauth/code-challenge (:code-verifier session)) (get (t/query url) "code_challenge")))
      (is (not (str/includes? url (:code-verifier session))) "the verifier isn't in the URL"))
    (testing "but not after :session-seconds, nor with another secret"
      (is (nil? (indieauth/state-session secret-text state {:now-fn (constantly #inst "2026-10-11T12:11:00Z")})))
      (is (nil? (indieauth/state-session (str secret-text "!") state {:now-fn (constantly noon)}))))))

(def session
  (assoc discovery
         :authorization-endpoint "https://auth.example/auth"
         :client-id              "https://app.example/"
         :redirect-uri           "https://app.example/callback"
         :scope                  "profile create"
         :state                  "the-state"
         :code-verifier          "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))

(def callback
  {"code" "the-code" "state" "the-state" "iss" "https://auth.example/"})

(deftest callbacks
  (is (nil? (indieauth/callback-problem session callback)))
  (is (nil? (indieauth/callback-problem session {:code "the-code" :state "the-state" :iss "https://auth.example/"}))
      "with keywords as keys")
  (testing "C301: a state that isn't the client's"
    (is (= ::indieauth/state-mismatch (:type (indieauth/callback-problem session (assoc callback "state" "changed")))))
    (is (= ::indieauth/state-mismatch (:type (indieauth/callback-problem session (dissoc callback "state"))))))
  (testing "C302: no iss"
    (is (= ::indieauth/issuer-mismatch (:type (indieauth/callback-problem session (dissoc callback "iss"))))))
  (testing "C303: the iss of another server"
    (is (= ::indieauth/issuer-mismatch (:type (indieauth/callback-problem session (assoc callback "iss" "https://decoy.example/"))))))
  (testing "C304: the same text alone"
    (is (= ::indieauth/issuer-mismatch (:type (indieauth/callback-problem session (assoc callback "iss" "https://auth.example"))))))
  (testing "C305: an error"
    (is (= {:type ::indieauth/authorization-error :code "access_denied" :reason "The user said no"}
           (indieauth/callback-problem session (-> (dissoc callback "code")
                                                   (assoc "error" "access_denied" "error_description" "The user said no"))))))
  (testing "C306: a state that the client never made"
    (is (= ::indieauth/state-mismatch (:type (indieauth/callback-problem session (assoc callback "state" "made-up"))))))
  (testing "the older links name no issuer"
    (is (nil? (indieauth/callback-problem (dissoc session :issuer) (dissoc callback "iss"))))))

(defn- token-endpoint
  "A Ring handler for the token endpoint that answers each redemption with
  `status` and the JSON of `x`, and conj's each request's body to the atom
  `bodies`."
  [bodies status x]
  (fn [{:keys [body]}]
    (swap! bodies conj (t/query (str "?" body)))
    ((t/json-doc status x) nil)))

(defn- redeemed
  "A step that redeems the callback `params` of `session` at a server
  whose token endpoint answers with `status` and the JSON of `x`, and
  calls `f` with the answer and the bodies that the endpoints got."
  [session params status x f]
  (fn []
    (let [bodies (atom [])
          routes {"https://tokens.example/token" (token-endpoint bodies status x)
                  "https://auth.example/auth"    (token-endpoint bodies status x)}]
      (async/then (indieauth/redeem! session params (world (atom []) routes))
                  #(f % @bodies)))))

(def answer
  {:access_token "a-token" :token_type "Bearer" :scope "profile create" :me "https://user.example/"})

(deftest redemptions
  (run
   (redeemed session callback 200 answer
             (fn [a [body]]
               (testing "C401: the code, redeemed at the token endpoint"
                 (is (= answer a))
                 (is (= {"grant_type"    "authorization_code"
                         "code"          "the-code"
                         "client_id"     "https://app.example/"
                         "redirect_uri"  "https://app.example/callback"
                         "code_verifier" "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
                        body)))))
   (redeemed session (dissoc callback "iss") 200 answer
             (fn [a bodies]
               (testing "no redemption after a problem"
                 (is (= ::indieauth/issuer-mismatch (-> a :error :type)))
                 (is (empty? bodies)))))
   (redeemed (assoc session :me "https://user.example/c402" :urls ["https://user.example/c402"])
             callback 200 (assoc answer :me "https://user.example/")
             (fn [a _]
               (testing "C402: another me on the same domain that names the same server"
                 (is (= "https://user.example/" (:me a))))))
   (redeemed session callback 200 (assoc answer :me "https://another.example/other-server")
             (fn [a _]
               (testing "C403: a me that names another server"
                 (is (= ::indieauth/unconfirmed (-> a :error :type))))))
   (redeemed session callback 200 (assoc answer :me "https://another.example")
             (fn [a _]
               (testing "C404: a me on another domain that names this server"
                 (is (= "https://another.example/" (:me a))))))
   (redeemed (assoc session :urls ["https://user.example/" "https://www.user.example/c106/"])
             callback 200 (assoc answer :me "https://www.user.example/c106/")
             (fn [a _]
               (testing "C405: a me that discovery went through"
                 (is (= "https://www.user.example/c106/" (:me a))))))
   (redeemed session callback 200 (dissoc answer :me)
             (fn [a _]
               (testing "C406: no me"
                 (is (= ::indieauth/no-me (-> a :error :type))))))
   (redeemed session callback 200 (assoc answer :me "https://user.example:8443/#me")
             (fn [a _]
               (testing "C407: a me that isn't a profile URL"
                 (is (= ::indieauth/invalid-me (-> a :error :type))))))
   (redeemed session callback 200 (assoc answer :profile {:url "https://another.example/" :email "someone@else.example"})
             (fn [a _]
               (testing "C408: the me, not the profile, says who the user is"
                 (is (= "https://user.example/" (:me a))))))
   (redeemed session callback 400 {:error "invalid_grant" :error_description "The code is used"}
             (fn [a _]
               (testing "C409: an error of the token endpoint"
                 (is (= {:type ::indieauth/redemption-error :code "invalid_grant" :status 400 :reason "The code is used"}
                        (:error a))))))
   (redeemed (assoc session :scope "profile") callback 200 {:me "https://user.example/" :profile {:name "A user"}}
             (fn [a _]
               (testing "C410: a code without a token scope, at the authorization endpoint"
                 (is (= {:me "https://user.example/" :profile {:name "A user"}} a)))))))

(deftest redemption-requests
  (is (= "https://tokens.example/token" (:url (indieauth/redemption-request session "c"))))
  (is (= "https://auth.example/auth" (:url (indieauth/redemption-request (assoc session :scope "profile email") "c"))))
  (is (not (str/includes? (pr-str (indieauth/redemption-request session "c")) "the-code"))
      "the body doesn't print"))

(deftest client-metadata
  (testing "C208 and C209: the document at the client identifier"
    (is (= {:client_id     "https://app.example/"
            :client_uri    "https://app.example/"
            :client_name   "An app"
            :redirect_uris ["https://login.app.example/callback"]}
           (indieauth/client-metadata (assoc client
                                             :client-name "An app"
                                             :redirect-uris ["https://login.app.example/callback"]))))
    (is (thrown? #?(:clj Exception :cljs :default)
                 (indieauth/client-metadata (assoc client :client-uri "https://elsewhere.example/")))))
  (let [handler (indieauth/client-metadata-handler client)
        r       (handler {:request-method :get :uri "/"})]
    (is (= 200 (:status r)))
    (is (= "application/json" (get-in r [:headers "Content-Type"])))
    (is (= {:client_id "https://app.example/" :client_uri "https://app.example/"} (json/read-object (:body r))))
    (is (= 405 (:status (handler {:request-method :post :uri "/"}))))))
