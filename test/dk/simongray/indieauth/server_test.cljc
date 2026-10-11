(ns dk.simongray.indieauth.server-test
  "The server: its metadata, the authorization request, consent and codes,
  the token endpoint, refresh tokens, revocation, introspection and
  userinfo, the stores, client information, profile information and the
  shapes of Ring requests. A
  case of indieauth.rocks's server tests is named by its number, with
  clients of the test's own."
  (:require #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.server :as server]
            [dk.simongray.indieauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.bytes :as bytes]
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.url :as url]))

(def verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
(def challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

(def clients
  "The clients of the tests, each by its client identifier."
  {"https://app.example/"   (indieauth/client-metadata-handler
                             {:client-id     "https://app.example/"
                              :client-name   "An app"
                              :logo-uri      "https://app.example/logo.png"
                              :redirect-uris ["https://login.app.example/callback"
                                              "https://login.app.example/q?keep=1"]})
   "https://html.example/"  (t/page (str "<link rel=redirect_uri href=https://login.html.example/cb>"
                                         "<div class=h-app><img class=u-logo src=/logo.png>"
                                         "<a class='u-url p-name' href=/>An HTML app</a></div>"))
   "https://liar.example/"  (t/json-doc {:client_id     "https://other.example/"
                                         :redirect_uris ["https://evil.example/callback"]})
   "https://apps.example/"  (t/page (str "<div class=h-app><a class='u-url p-name' href=https://maker.example/>A maker</a></div>"
                                         "<div class=h-app><a class='u-url p-name' href=/>The app</a></div>"))
   "https://bare.example/"  (t/page "<div class=h-app><span class=p-name>A bare app</span></div>")
   "https://text.example/"  (constantly {:status 200 :headers {"Content-Type" "text/plain"} :body "An app"})
   "https://user.example/"  (t/page (str "<link rel=me href=https://social.example/@ann>"
                                         "<div class=h-card><a class='u-url p-name' href=/>Ann</a>"
                                         "<img class=u-photo src=/ann.jpg alt=''>"
                                         "<a class=u-email href=mailto:ann@user.example>mail</a></div>"))})

(def noon #inst "2026-10-11T12:00:00Z")

(defn- seconds-after
  "The instant `n` seconds after the instant `at`."
  [at n]
  (let [ms (+ (inst-ms at) (* 1000 n))]
    #?(:clj  (java.util.Date. (long ms))
       :cljs (js/Date. ms))))

(defn- server-opts
  "The options of a server with new stores, whose clock is in the atom
  `clock`, and which logs each request it sends to the atom `log`."
  ([]
   (server-opts (atom noon) (atom [])))
  ([clock log]
   {:issuer                 "https://auth.example/"
    :authorization-endpoint "https://auth.example/auth"
    :token-endpoint         "https://auth.example/token"
    :secret                 "a secret of thirty-two bytes, at least"
    :scopes-supported       ["profile" "email" "create" "update"]
    :codes                  (server/memory-store (atom {}) #(deref clock))
    :tokens                 (server/memory-store (atom {}) #(deref clock))
    :now-fn                 #(deref clock)
    :send                   (t/network clients log)
    :authorize              (fn [_ request]
                              {:status 200 :headers {} :body (pr-str request)})}))

(defn- request-params
  "The parameters of an authorization request from the app, with `more`."
  [& {:as more}]
  (merge {"response_type"         "code"
          "client_id"             "https://app.example/"
          "redirect_uri"          "https://app.example/callback"
          "state"                 "a state"
          "code_challenge"        challenge
          "code_challenge_method" "S256"
          "scope"                 "profile create"}
         more))

(defn- authorize
  "The response of the authorization endpoint of `opts` to a GET with the
  query `params`, a map or pairs."
  [opts params]
  ((server/handler opts) {:request-method :get
                          :uri            "/auth"
                          :query-string   (url/query-string params)}))

(defn- location
  "The query parameters of the Location of the `response`, by name."
  [response]
  (t/query (get-in response [:headers "Location"])))

(defn- checked
  "The authorization request that the :authorize of server-opts got, from
  the body of its `response`."
  [response]
  (edn/read-string (:body response)))

(deftest metadata
  (let [opts (server-opts)
        m    (server/metadata opts)]
    (testing "S104 to S112"
      (is (= {:issuer                                         "https://auth.example/"
              :authorization_endpoint                         "https://auth.example/auth"
              :token_endpoint                                 "https://auth.example/token"
              :scopes_supported                               ["profile" "email" "create" "update"]
              :response_types_supported                       ["code"]
              :grant_types_supported                          ["authorization_code" "refresh_token"]
              :code_challenge_methods_supported               ["S256"]
              :authorization_response_iss_parameter_supported true}
             m)))
    (testing "S108 and S113: the endpoints of phase 2, and revocation without client authentication"
      (is (= {:introspection_endpoint                     "https://auth.example/introspect"
              :revocation_endpoint                        "https://auth.example/revoke"
              :revocation_endpoint_auth_methods_supported ["none"]
              :userinfo_endpoint                          "https://auth.example/userinfo"}
             (select-keys (server/metadata (assoc opts
                                                  :introspection-endpoint "https://auth.example/introspect"
                                                  :revocation-endpoint "https://auth.example/revoke"
                                                  :userinfo-endpoint "https://auth.example/userinfo"))
                          [:introspection_endpoint :revocation_endpoint
                           :revocation_endpoint_auth_methods_supported :userinfo_endpoint])))
      (is (= ["authorization_code"] (:grant_types_supported (server/metadata (assoc opts :refresh-seconds nil))))
          "without refresh tokens"))
    (testing "S104 and S114: JSON that a page can read"
      (let [r ((server/metadata-handler opts) {:request-method :get})]
        (is (= 200 (:status r)))
        (is (= "application/json" (get-in r [:headers "Content-Type"])))
        (is (= "*" (get-in r [:headers "Access-Control-Allow-Origin"])))
        (is (= m (json/read-json (:body r))))))
    (testing "S117: at the well-known URL by default"
      (is (= "https://auth.example/.well-known/oauth-authorization-server" (:href (first (server/links opts))))))
    (testing "S115: the older links name the same endpoints"
      (is (= [{:rel "indieauth-metadata" :href "https://auth.example/.well-known/oauth-authorization-server"}
              {:rel "authorization_endpoint" :href "https://auth.example/auth"}
              {:rel "token_endpoint" :href "https://auth.example/token"}]
             (server/links opts)))
      (is (str/starts-with? (server/link-header opts)
                            "<https://auth.example/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\", ")))
    (testing "S105: an issuer that isn't a prefix of the metadata URL"
      (is (thrown? #?(:clj Exception :cljs :default)
                   (server/metadata (assoc opts :metadata-url "https://elsewhere.example/meta"))))
      (is (thrown? #?(:clj Exception :cljs :default)
                   (server/metadata (assoc opts :issuer "http://auth.example/")))))))

(deftest authorization-requests
  (let [log  (atom [])
        opts (server-opts (atom noon) log)
        step (fn [params f]
               #(async/then (authorize opts params) f))]
    (run
     (step (request-params)
           (fn [r]
             (testing "a request that's right goes to :authorize"
               (is (= 200 (:status r)))
               (is (= {:client-id      "https://app.example/"
                       :redirect-uri   "https://app.example/callback"
                       :state          "a state"
                       :code-challenge challenge
                       :scopes         ["profile" "create"]
                       :client         {:client-id   "https://app.example/"
                                        :client-uri  "https://app.example/"
                                        :client-name "An app"
                                        :logo-uri    "https://app.example/logo.png"}}
                      (checked r))))
             (testing "S205: the client identifier is fetched"
               (is (= ["https://app.example/"] (map :url @log))))
             (testing "S902: the page can't be framed"
               (is (= "DENY" (get-in r [:headers "X-Frame-Options"])))
               (is (= "frame-ancestors 'none'" (get-in r [:headers "Content-Security-Policy"]))))))
     (step (request-params "me" "user.example")
           (fn [r]
             (testing "S220: the me is a hint"
               (is (= "https://user.example/" (:me (checked r)))))))
     (step (request-params "redirect_uri" "https://login.app.example/callback")
           (fn [r]
             (testing "S209: a registered redirect URL on another host"
               (is (= 200 (:status r))))))
     (step (request-params "client_id" "https://html.example/" "redirect_uri" "https://login.html.example/cb")
           (fn [r]
             (testing "an HTML page with an h-app and redirect_uri links"
               (is (= 200 (:status r)))
               (is (= {:client-id   "https://html.example/"
                       :client-name "An HTML app"
                       :client-uri  "https://html.example/"
                       :logo-uri    "https://html.example/logo.png"}
                      (:client (checked r)))))))
     (step (request-params "redirect_uri" "https://evil.example/callback")
           (fn [r]
             (testing "S208: an unregistered redirect URL on another host"
               (is (= 400 (:status r)))
               (is (nil? (get-in r [:headers "Location"]))))))
     (step (request-params "redirect_uri" "https://login.app.example/callback/more")
           (fn [r]
             (testing "S210: a redirect URL that a registered one is a prefix of"
               (is (= 400 (:status r))))))
     (step (request-params "redirect_uri" "https://app.example@evil.example/callback")
           (fn [r]
             (testing "S211: credentials in a redirect URL"
               (is (= 400 (:status r))))))
     (step (request-params "client_id" "https://liar.example/" "redirect_uri" "https://evil.example/callback")
           (fn [r]
             (testing "S212: a client metadata document for another client"
               (is (= 400 (:status r))))))
     (step (conj (vec (request-params)) ["redirect_uri" "https://evil.example/callback"])
           (fn [r]
             (testing "S213: a repeated redirect_uri"
               (is (= 400 (:status r)))
               (is (nil? (get-in r [:headers "Location"]))))))
     (step (dissoc (request-params "redirect_uri" "https://evil.example/") "client_id")
           (fn [r]
             (testing "S214: no client_id"
               (is (= 400 (:status r)))
               (is (nil? (get-in r [:headers "Location"]))))))
     (step (request-params "client_id" "https://app.example/a/../")
           (fn [r]
             (testing "S219: a client_id that isn't valid"
               (is (= 400 (:status r))))))
     (step (request-params "redirect_uri" "javascript:alert(1)")
           (fn [r]
             (testing "a redirect URL that a browser runs"
               (is (= 400 (:status r)))))))))

(deftest without-client-info
  (let [log  (atom [])
        opts (assoc (server-opts (atom noon) log) :client-info? false)]
    (run
     #(async/then (authorize opts (request-params))
                  (fn [r]
                    (testing "without :client-info?, a redirect URL on the client's host needs no fetch"
                      (is (= 200 (:status r)))
                      (is (= {:client-id "https://app.example/"} (:client (checked r))))
                      (is (empty? @log)))))
     #(async/then (authorize opts (request-params "redirect_uri" "https://login.app.example/callback"))
                  (fn [r]
                    (testing "but one on another host does"
                      (is (= 200 (:status r)))
                      (is (= ["https://app.example/"] (map :url @log)))))))))

(defn- error-redirect
  "A step that sends the authorization request of `params` to a new server
  and calls `f` with the query parameters of the redirect it gives."
  [params f]
  #(async/then (authorize (server-opts) params)
               (fn [r]
                 (is (= 302 (:status r)))
                 (f (location r)))))

(deftest authorization-request-errors
  (run
   (error-redirect (request-params "state" "a+b c/d=é%20" "code_challenge_method" "plain")
                   (fn [q]
                     (testing "S201 and S202: with an error, the state as it was sent, and iss"
                       (is (= "a+b c/d=é%20" (q "state")))
                       (is (= "https://auth.example/" (q "iss"))))))
   (error-redirect (dissoc (request-params) "code_challenge" "code_challenge_method")
                   (fn [q]
                     (testing "S215: PKCE is required"
                       (is (= "invalid_request" (q "error")))
                       (is (= "a state" (q "state"))))))
   (error-redirect (request-params "code_challenge_method" "plain" "code_challenge" verifier)
                   (fn [q]
                     (testing "S216: not the plain method"
                       (is (= "invalid_request" (q "error"))))))
   (error-redirect (request-params "response_type" "token")
                   (fn [q]
                     (testing "S217: not the implicit flow"
                       (is (= "unsupported_response_type" (q "error")))
                       (is (nil? (q "access_token"))))))
   (error-redirect (dissoc (request-params) "state")
                   (fn [q]
                     (testing "S218: no state"
                       (is (= "invalid_request" (q "error")))
                       (is (nil? (q "state"))))))
   (error-redirect (dissoc (request-params) "code_challenge")
                   (fn [q]
                     (testing "S221: a method without a challenge"
                       (is (= "invalid_request" (q "error"))))))
   (error-redirect (dissoc (request-params) "code_challenge_method")
                   (fn [q]
                     (testing "S222: a challenge without a method"
                       (is (= "invalid_request" (q "error"))))))
   (error-redirect (request-params "scope" "email create")
                   (fn [q]
                     (testing "email without profile"
                       (is (= "invalid_scope" (q "error"))))))
   (error-redirect (request-params "scope" "profile a\"b")
                   (fn [q]
                     (testing "RFC 6749, section 3.3: a scope with a character that a scope can't have"
                       (is (= "invalid_scope" (q "error"))))))
   (error-redirect (conj (vec (request-params)) ["scope" "create"])
                   (fn [q]
                     (testing "another repeated parameter"
                       (is (= "invalid_request" (q "error"))))))))

(defn- approved
  "A step that checks the authorization request of `params` with `opts`,
  shows consent to `me`, approves the `grant` and calls `f` with the
  answer of approve!."
  [opts params me grant f]
  #(async/then (server/authorization-request! params opts)
               (fn [{:keys [request]}]
                 (async/then (server/approve! (:token (server/consent request me opts)) grant opts)
                             f))))

(deftest consent-and-codes
  (let [opts (server-opts)]
    (testing "consent for a user who isn't a profile URL"
      (is (thrown? #?(:clj Exception :cljs :default)
                   (server/consent {:client-id "https://app.example/"} "https://user.example:8443/" opts))))
    (testing "an authorization endpoint without :authorize"
      (is (thrown? #?(:clj Exception :cljs :default)
                   (server/handler (dissoc opts :authorize)))))
    (run
     #(async/then (server/authorization-request! (request-params "scope" "profile email create") opts)
                  (fn [{:keys [request]}]
                    (let [c (server/consent request "https://user.example" opts)]
                      (testing "S206: consent names the application and the user"
                        (is (= "https://app.example/" (:client-id c)))
                        (is (= "An app" (get-in c [:client :client-name])))
                        (is (= "https://user.example/" (:me c)))
                        (is (= ["profile" "email" "create"] (:scopes c))))
                      (testing "the request comes back from the token"
                        (is (= request (server/token-request (:token c) opts)))
                        (is (= request (server/token-request (server/request-token request opts) opts)))
                        (is (nil? (server/token-request (:token c) (assoc opts :now-fn (constantly #inst "2026-10-11T13:00:00Z"))))))
                      (testing "S207: the user says no"
                        (let [q (t/query (server/denial request opts))]
                          (is (= ["access_denied" "a state" "https://auth.example/"]
                                 [(q "error") (q "state") (q "iss")])))))))
     (approved opts (request-params "redirect_uri" "https://login.app.example/q?keep=1")
               "https://user.example/" {:me "https://user.example/"}
               (fn [{:keys [redirect]}]
                 (let [q (t/query redirect)]
                   (testing "S203: a code"
                     (is (<= 22 (count (q "code")))))
                   (testing "S204: the query of the redirect URL stays"
                     (is (str/starts-with? redirect "https://login.app.example/q?keep=1&code=")))
                   (testing "S201 and S202"
                     (is (= "a state" (q "state")))
                     (is (= "https://auth.example/" (q "iss"))))
                   (testing "S905: no token in the URL"
                     (is (nil? (q "access_token")))))))
     (approved opts (request-params "me" "https://mallory.example/")
               "https://user.example/" {:me "https://mallory.example/"}
               (fn [a]
                 (testing "S220: the me of the user who is signed in, not the client's"
                   (is (= "access_denied" (-> a :error :code))))))
     (approved opts (request-params) "https://user.example/" {:me "https://user.example:8443/"}
               (fn [a]
                 (testing "a me that isn't a profile URL"
                   (is (some? (:error a))))))
     #(async/then (server/approve! "forged.token" {:me "https://user.example/"} opts)
                  (fn [a]
                    (testing "a consent that the server didn't sign"
                      (is (= "invalid_request" (-> a :error :code)))))))))

(defn- redeem
  "The response of the endpoint `h` of `opts` to a POST of the form
  `fields`."
  [h fields]
  (h {:request-method :post
      :headers        {"content-type" "application/x-www-form-urlencoded"}
      :body           (url/query-string fields)}))

(defn- redemption
  "The fields of a redemption of the code in the `redirect` of approve!,
  with `more`."
  [redirect & {:as more}]
  (merge {"grant_type"    "authorization_code"
          "code"          ((t/query redirect) "code")
          "client_id"     "https://app.example/"
          "redirect_uri"  "https://app.example/callback"
          "code_verifier" verifier}
         more))

(defn- code-step
  "A step that approves a request of `params` for the user with the
  `grant`, redeems the code at the token endpoint of `opts` with the
  fields of `more`, and calls `f` with the response and the redirect of
  the code."
  [opts params grant more f]
  (approved opts params "https://user.example/" (merge {:me "https://user.example/"} grant)
            (fn [{:keys [redirect]}]
              (async/then (redeem (server/token-handler opts) (merge (redemption redirect) more))
                          #(f % redirect)))))

(defn- answer
  "The JSON of the body of the `response`."
  [response]
  (json/read-json (:body response)))

(deftest token-endpoint
  (let [clock (atom noon)
        opts  (assoc (server-opts clock (atom [])) :token-seconds 3600)
        token (server/token-handler opts)
        fail? (fn [r code]
                (is (= 400 (:status r)))
                (is (= code (:error (answer r))) "S332: JSON with an error"))]
    (run
     (code-step opts (request-params "scope" "profile email create") {:scopes  ["profile" "create"]
                                                                      :profile {:name "Ann" :email "ann@user.example" :photo 42}}
                {}
                (fn [r redirect]
                  (let [a (answer r)]
                    (testing "S301 and S401: an access token, as JSON"
                      (is (= 200 (:status r)))
                      (is (= "application/json" (get-in r [:headers "Content-Type"]))))
                    (testing "S402, S403, S404, S407 and S408"
                      (is (= {:token_type "Bearer"
                              :scope      "profile create"
                              :me         "https://user.example/"
                              :expires_in 3600
                              :profile    {:name "Ann"}}
                             (dissoc a :access_token :refresh_token))
                          "S409: the profile that the scopes grant, of texts")
                      (is (string? (:refresh_token a)) "and a refresh token"))
                    (testing "S406: no cache keeps it"
                      (is (= "no-store" (get-in r [:headers "Cache-Control"]))))
                    (testing "S410: an access token that nobody can guess"
                      (is (<= 22 (count (:access_token a)))))
                    (async/then (redeem token (redemption redirect))
                                (fn [r]
                                  (testing "S302: a code works once"
                                    (fail? r "invalid_grant")))))))
     (code-step opts (request-params) {} {"code_verifier" (str/reverse verifier)}
                (fn [r redirect]
                  (testing "S310: a wrong verifier"
                    (fail? r "invalid_grant"))
                  (async/then (redeem token (redemption redirect))
                              (fn [r]
                                (testing "and the code is gone"
                                  (fail? r "invalid_grant"))))))
     (code-step opts (request-params) {} {"code_verifier" nil}
                (fn [r _]
                  (testing "S311: no verifier"
                    (fail? r "invalid_grant"))))
     (code-step opts (request-params) {} {"client_id" "https://other.example/"}
                (fn [r _]
                  (testing "S312: the code of another client"
                    (fail? r "invalid_grant"))))
     (code-step opts (request-params) {} {"redirect_uri" "https://app.example/other"}
                (fn [r _]
                  (testing "S313: another redirect_uri"
                    (fail? r "invalid_grant"))))
     (code-step opts (dissoc (request-params) "scope") {} {}
                (fn [r _]
                  (testing "S320 and S321: a code without a scope gives the me alone"
                    (is (= 200 (:status r)))
                    (is (= {:me "https://user.example/"} (answer r))))))
     (code-step opts (request-params "scope" "create") {:scopes []} {}
                (fn [r _]
                  (testing "a user who grants no scope"
                    (is (= {:me "https://user.example/"} (answer r))))))
     (approved opts (request-params) "https://user.example/" {:me "https://user.example/"}
               (fn [{:keys [redirect]}]
                 (swap! clock seconds-after 61)
                 (async/then (redeem token (redemption redirect))
                             (fn [r]
                               (reset! clock noon)
                               (testing "S304: a code expires"
                                 (fail? r "invalid_grant"))))))
     #(async/then (redeem token (redemption "?code=made-up"))
                  (fn [r]
                    (testing "S330: an unknown code"
                      (fail? r "invalid_grant"))))
     #(async/then (redeem token (dissoc (redemption "?code=c") "grant_type"))
                  (fn [r]
                    (testing "S331: no grant_type"
                      (fail? r "invalid_request"))))
     #(async/then (redeem token (redemption "?code=c" "grant_type" "password"))
                  (fn [r]
                    (testing "S331: another grant_type"
                      (fail? r "unsupported_grant_type"))))
     #(async/then (redeem token (dissoc (redemption "?code=c") "redirect_uri"))
                  (fn [r]
                    (testing "no redirect_uri"
                      (fail? r "invalid_request"))))
     #(async/then (redeem token (conj (vec (redemption "?code=c")) ["code" "d"]))
                  (fn [r]
                    (testing "RFC 6749, section 3.2: a repeated parameter"
                      (fail? r "invalid_request"))))
     #(async/then (redeem (server/token-handler (assoc opts :max-form-bytes 64)) (redemption "?code=c"))
                  (fn [r]
                    (testing "a form that's too large"
                      (is (= 413 (:status r))))))
     #(async/then (token {:request-method :get :query-string (url/query-string (redemption "?code=c"))})
                  (fn [r]
                    (testing "S333: not a GET"
                      (is (= 405 (:status r)))
                      (is (= "OPTIONS, POST" (get-in r [:headers "Allow"]))))))
     #(async/then (token {:request-method :options})
                  (fn [r]
                    (testing "S334 and S906: a preflight, without credentials"
                      (is (= "*" (get-in r [:headers "Access-Control-Allow-Origin"])))
                      (is (nil? (get-in r [:headers "Access-Control-Allow-Credentials"])))))))))

(deftest authorization-endpoint-redemption
  (let [opts (server-opts)
        h    (server/handler opts)]
    (run
     (approved opts (request-params "scope" "profile") "https://user.example/"
               {:me "https://user.example/" :profile {:name "Ann" :url "https://user.example/"}}
               (fn [{:keys [redirect]}]
                 (async/then (redeem h (dissoc (redemption redirect) "grant_type"))
                             (fn [r]
                               (testing "section 5.3.2: the me and the profile, from an older client too"
                                 (is (= 200 (:status r)))
                                 (is (= {:me "https://user.example/" :profile {:name "Ann" :url "https://user.example/"}}
                                        (answer r))))
                               (async/then (redeem h (redemption redirect))
                                           (fn [r]
                                             (testing "S302 there too: a code works once"
                                               (is (= "invalid_grant" (:error (answer r)))))))))))
     (approved opts (request-params "scope" "profile") "https://user.example/" {:me "https://user.example/"}
               (fn [{:keys [redirect]}]
                 (async/then (redeem h (redemption redirect "code_verifier" (str/reverse verifier)))
                             (fn [r]
                               (testing "S310 there too: a wrong verifier"
                                 (is (= "invalid_grant" (:error (answer r)))))))))
     #(async/then (redeem h (redemption "?code=c" "grant_type" "refresh_token"))
                  (fn [r]
                    (testing "and no other grant"
                      (is (= "unsupported_grant_type" (:error (answer r))))))))))

(deftest stores
  (let [clock (atom noon)
        store (server/memory-store (atom {}) #(deref clock))]
    ((:put! store) "a" {:x 1 :expires #inst "2026-10-11T12:01:00Z"})
    ((:put! store) "b" {:x 2})
    (is (= {:x 2} ((:get store) "b")))
    (testing "take! gives a value once"
      (is (= {:x 2} ((:take! store) "b")))
      (is (nil? ((:take! store) "b"))))
    (testing "an expired value is dropped"
      (reset! clock #inst "2026-10-11T12:02:00Z")
      ((:put! store) "c" {:x 3})
      (is (nil? ((:get store) "a")))))
  (testing "a key is the SHA-256 of a code or a token, not the text"
    (is (= "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564" (digest/text "foo")))))

(deftest client-information
  (let [opts {:send (t/network clients)}]
    (run
     #(async/then (server/client-info! "https://app.example/" opts)
                  (fn [info]
                    (testing "a client metadata document"
                      (is (= {:client-id     "https://app.example/"
                              :client-uri    "https://app.example/"
                              :client-name   "An app"
                              :logo-uri      "https://app.example/logo.png"
                              :redirect-uris ["https://login.app.example/callback" "https://login.app.example/q?keep=1"]}
                             info)))))
     #(async/then (server/client-info! "https://apps.example/" opts)
                  (fn [info]
                    (testing "the h-app of the client, before others on its page"
                      (is (= "The app" (:client-name info))))))
     #(async/then (server/client-info! "https://bare.example/" opts)
                  (fn [info]
                    (testing "or else the first"
                      (is (= {:client-id "https://bare.example/" :client-name "A bare app" :redirect-uris []} info)))))
     #(async/then (server/client-info! "https://text.example/" opts)
                  (fn [info]
                    (testing "a page that's neither JSON nor HTML"
                      (is (= {:client-id "https://text.example/" :redirect-uris []} info)))))
     #(async/then (server/client-info! "https://liar.example/" opts)
                  (fn [info]
                    (testing "a document for another client"
                      (is (= {:client-id "https://liar.example/" :redirect-uris []} info)))))
     #(async/then (server/client-info! "https://missing.example/" opts)
                  (fn [info]
                    (testing "a client identifier that fails"
                      (is (= 404 (-> info :error :status)))
                      (is (= [] (:redirect-uris info))))))
     #(let [log (atom [])]
        (async/then (server/client-info! "http://127.0.0.1:8080/" {:send (t/network clients log)})
                    (fn [info]
                      (testing "section 4.2: a loopback client isn't fetched"
                        (is (= {:client-id "http://127.0.0.1:8080/" :redirect-uris []} info))
                        (is (empty? @log))))))
     #(let [log (atom [])]
        (async/then (server/client-info! "http://localhost:3000/" {:send (t/network clients log)})
                    (fn [_]
                      (testing "nor one on localhost"
                        (is (empty? @log)))))))))

(defn- async-response
  "The response that the Ring handler `h` gives `request` as an
  asynchronous handler, or what it raises, as a value or a promise, or
  ::timeout on the JVM when it does neither."
  [h request]
  #?(:clj  (let [p (promise)]
             (h request #(deliver p %) #(deliver p %))
             (deref p 10000 ::timeout))
     :cljs (js/Promise. (fn [resolve _] (h request resolve resolve)))))

(deftest ring-requests
  (let [opts (server-opts)]
    (run
     #(async/then ((server/handler opts) {:request-method :get :query-params (request-params)})
                  (fn [r]
                    (testing "a query that wrap-params has read"
                      (is (= 200 (:status r))))))
     #(async/then ((server/token-handler opts) {:request-method :post :form-params {:grant_type "password"}})
                  (fn [r]
                    (testing "a form that wrap-params has read"
                      (is (= "unsupported_grant_type" (:error (answer r)))))))
     #(async/then ((server/token-handler opts) {:request-method :post :body (bytes/encode "grant_type=password")})
                  (fn [r]
                    (testing "a body of bytes"
                      (is (= "unsupported_grant_type" (:error (answer r)))))))
     #(async/then ((server/revocation-handler opts) {:request-method :post})
                  (fn [r]
                    (testing "no body"
                      (is (= "invalid_request" (:error (answer r)))))))
     #(async/then (async-response (server/metadata-handler opts) {:request-method :get})
                  (fn [r]
                    (testing "an asynchronous handler"
                      (is (= 200 (:status r))))))
     #(async/then (async-response (server/handler (assoc opts :authorize (fn [_ _] (throw (ex-info "The page broke" {})))))
                                  {:request-method :get :query-string (url/query-string (request-params))})
                  (fn [e]
                    (testing "which raises what a function of yours throws"
                      (is (= "The page broke" (ex-message e)))))))))

(deftest profiles
  (is (nil? (server/profile {:url "https://user.example/" :body "<p class=h-card><a class=u-url href=https://other.example/>B</a>"}))
      "an h-card of another page")
  (is (= {:name "Ann" :url "https://social.example/@ann"}
         (server/profile {:url  "https://user.example/"
                          :body (str "<link rel=me href=https://social.example/@ann>"
                                     "<p class=h-card><a class='u-url p-name' href=https://bob.example/>Bob</a>"
                                     "<p class=h-card><a class='u-url p-name' href=https://social.example/@ann>Ann</a>")}))
      "the h-card whose url is that of a rel=me link")
  (run
   #(async/then (server/profile! "https://user.example/" {:send (t/network clients)})
                (fn [p]
                  (testing "the representative h-card"
                    (is (= {:name  "Ann"
                            :url   "https://user.example/"
                            :photo "https://user.example/ann.jpg"
                            :email "ann@user.example"}
                           p)))))))

;; phase 2: refresh tokens, revocation, introspection and userinfo

(def resource-token "the-token-of-a-resource-server")

(defn- phase-2-opts
  "The options of a server with the endpoints of phase 2, whose clock is in
  the atom `clock`."
  [clock]
  (assoc (server-opts clock (atom []))
         :revocation-endpoint    "https://auth.example/revoke"
         :introspection-endpoint "https://auth.example/introspect"
         :userinfo-endpoint      "https://auth.example/userinfo"
         :resource-tokens        [resource-token]))

(defn- signed-in
  "A step that signs the user in at the server of `opts` with the `scope`,
  and calls `f` with the answer of the token endpoint."
  [opts scope f]
  (code-step opts (request-params "scope" scope)
             {:profile {:name "Ann" :url "https://user.example/" :email "ann@user.example"}}
             {}
             (fn [r _] (f (answer r)))))

(defn- post
  "The response of the handler `h` to a POST of the form `fields`, with the
  bearer `token` when it's given."
  ([h fields]
   (post h fields nil))
  ([h fields token]
   (h {:request-method :post
       :headers        (cond-> {"content-type" "application/x-www-form-urlencoded"}
                         token (assoc "authorization" (str "Bearer " token)))
       :body           (url/query-string fields)})))

(defn- bearer
  "A GET with the bearer `token`."
  [token]
  {:request-method :get :headers {"authorization" (str "Bearer " token)}})

(defn- refresh-fields
  "The fields of a refresh of the `refresh-token` by the app, with `more`."
  [refresh-token & {:as more}]
  (merge {"grant_type"    "refresh_token"
          "refresh_token" refresh-token
          "client_id"     "https://app.example/"}
         more))

(deftest refresh-tokens
  (let [opts   (phase-2-opts (atom noon))
        token  (server/token-handler opts)
        first  (atom nil)
        newest (atom nil)]
    (run
     (signed-in opts "profile create update" #(reset! first %))
     #(async/then (post token (refresh-fields (:refresh_token @first)))
                  (fn [r]
                    (let [a (answer r)]
                      (testing "S501: a new access token with the me, which no cache keeps"
                        (is (= 200 (:status r)))
                        (is (= "no-store" (get-in r [:headers "Cache-Control"])))
                        (is (= {:me         "https://user.example/"
                                :scope      "profile create update"
                                :token_type "Bearer"
                                :expires_in 86400
                                :profile    {:name "Ann" :url "https://user.example/"}}
                               (dissoc a :access_token :refresh_token)))
                        (is (not= (:access_token @first) (:access_token a))))
                      (testing "and a new refresh token, since one works once"
                        (is (string? (:refresh_token a)))
                        (is (not= (:refresh_token @first) (:refresh_token a))))
                      (reset! newest a))))
     #(async/then (post token (refresh-fields (:refresh_token @newest) "client_id" "https://other.example/"))
                  (fn [r]
                    (testing "S502: not for another client"
                      (is (= "invalid_grant" (:error (answer r)))))))
     #(async/then (post token (refresh-fields (:refresh_token @newest) "scope" "create delete"))
                  (fn [r]
                    (testing "S503: not for more scopes"
                      (is (= "invalid_scope" (:error (answer r)))))))
     #(async/then (post token (refresh-fields (:refresh_token @newest) "scope" "create"))
                  (fn [r]
                    (let [a (answer r)]
                      (testing "for fewer scopes"
                        (is (= "create" (:scope a)))
                        (is (nil? (:profile a)) "and no profile without the profile scope"))
                      (reset! newest a))))
     #(async/then (post token (refresh-fields (:refresh_token @newest)))
                  (fn [r]
                    (let [a (answer r)]
                      (testing "section 5.5.1: the new refresh token keeps the scopes of the old"
                        (is (= "profile create update" (:scope a))))
                      (reset! newest a))))
     #(async/then (post token (dissoc (refresh-fields (:refresh_token @newest)) "client_id"))
                  (fn [r]
                    (testing "no client_id"
                      (is (= "invalid_request" (:error (answer r)))))))
     #(async/then (post token (refresh-fields (:refresh_token @newest) "scope" "a\"b"))
                  (fn [r]
                    (testing "a scope with a character that a scope can't have"
                      (is (= "invalid_scope" (:error (answer r)))))))
     #(async/then (post token (refresh-fields (:refresh_token @first)))
                  (fn [r]
                    (testing "S504: an old refresh token stops working"
                      (is (= "invalid_grant" (:error (answer r)))))))
     #(async/then (resource/token-info! (:access_token @newest) opts)
                  (fn [i]
                    (testing "S505: and using it revokes the grant, the newest tokens too"
                      (is (nil? i)))))
     #(async/then (post token (refresh-fields (:refresh_token @newest)))
                  (fn [r]
                    (is (= "invalid_grant" (:error (answer r)))))))))

(deftest refresh-races
  (let [a     (atom {})
        clock (atom noon)
        opts  (assoc (phase-2-opts clock) :tokens (server/memory-store a #(deref clock)))
        b     (atom nil)]
    (run
     (signed-in opts "create" #(reset! b %))
     #(async/then (post (server/token-handler (assoc-in opts [:tokens :take!] (constantly nil)))
                        (refresh-fields (:refresh_token @b)))
                  (fn [r]
                    (testing "a refresh token that another refresh took first"
                      (is (= "invalid_grant" (:error (answer r)))))))
     #(do (swap! a (fn [m] (into {} (remove (fn [[k _]] (str/starts-with? k "grant:"))) m)))
          (async/then (post (server/token-handler opts) (refresh-fields (:refresh_token @b)))
                      (fn [r]
                        (testing "a grant revoked while its refresh token is checked"
                          (is (= "invalid_grant" (:error (answer r)))))))))))

(deftest token-lifetimes
  (let [clock (atom noon)
        opts  (phase-2-opts clock)
        token (server/token-handler opts)
        a     (atom nil)]
    (run
     (signed-in opts "create" #(reset! a %))
     #(do (swap! clock seconds-after 86400)
          (async/then (resource/token-info! (:access_token @a) opts)
                      (fn [i]
                        (testing "an access token lasts a day"
                          (is (nil? i))))))
     #(async/then (post token (refresh-fields (:refresh_token @a)))
                  (fn [r]
                    (testing "and its refresh token lasts longer"
                      (is (= 200 (:status r))))
                    (reset! a (answer r))))
     #(do (swap! clock seconds-after (* 30 86400))
          (async/then (post token (refresh-fields (:refresh_token @a)))
                      (fn [r]
                        (testing "but a refresh token unused for 30 days expires"
                          (is (= "invalid_grant" (:error (answer r))))))))
     (signed-in (assoc opts :refresh-seconds nil :token-seconds nil) "create" #(reset! a %))
     #(async/then (post token (refresh-fields "anything"))
                  (fn [_]
                    (testing "without refresh tokens, a token that lasts for ever"
                      (is (nil? (:refresh_token @a)))
                      (is (nil? (:expires_in @a))))))
     #(async/then (post (server/token-handler (assoc opts :refresh-seconds nil)) (refresh-fields "anything"))
                  (fn [r]
                    (testing "and no refresh grant"
                      (is (= "unsupported_grant_type" (:error (answer r))))))))))

(deftest code-reuse
  (let [opts     (phase-2-opts (atom noon))
        token    (server/token-handler opts)
        first    (atom nil)
        redirect (atom nil)]
    (run
     (code-step opts (request-params) {} {}
                (fn [r rd]
                  (reset! first (answer r))
                  (reset! redirect rd)))
     #(async/then (post token (redemption @redirect))
                  (fn [r]
                    (testing "S302: a code works once"
                      (is (= "invalid_grant" (:error (answer r)))))))
     #(async/then (resource/token-info! (:access_token @first) opts)
                  (fn [i]
                    (testing "S303: a code used again revokes the tokens it gave"
                      (is (nil? i)))))
     #(async/then (post token (refresh-fields (:refresh_token @first)))
                  (fn [r]
                    (testing "its refresh token too"
                      (is (= "invalid_grant" (:error (answer r))))))))))

(deftest revocation
  (let [opts     (phase-2-opts (atom noon))
        revoke   (server/revocation-handler opts)
        token    (server/token-handler opts)
        userinfo (server/userinfo-handler opts)
        a        (atom nil)
        b        (atom nil)]
    (run
     (signed-in opts "profile create" #(reset! a %))
     #(async/then (post revoke {"token" (:access_token @a)})
                  (fn [r]
                    (testing "S601: an access token"
                      (is (= 200 (:status r))))))
     #(async/then (userinfo (bearer (:access_token @a)))
                  (fn [r]
                    (testing "S602: which stops working"
                      (is (= 401 (:status r))))))
     #(async/then (post token (refresh-fields (:refresh_token @a)))
                  (fn [r]
                    (testing "while its refresh token still works"
                      (is (= 200 (:status r))))
                    (reset! b (answer r))))
     #(async/then (post revoke {"token" (:refresh_token @b) "token_type_hint" "refresh_token"})
                  (fn [r]
                    (testing "S603: a refresh token"
                      (is (= 200 (:status r))))))
     #(async/then (post token (refresh-fields (:refresh_token @b)))
                  (fn [r]
                    (testing "which stops working"
                      (is (= "invalid_grant" (:error (answer r)))))))
     #(async/then (resource/token-info! (:access_token @b) opts)
                  (fn [i]
                    (testing "RFC 7009, section 2.1: and so do the access tokens of its grant"
                      (is (nil? i)))))
     #(async/then (post revoke {"token" "made-up"})
                  (fn [r]
                    (testing "S604: an unknown token"
                      (is (= 200 (:status r))))))
     #(async/then (post revoke {})
                  (fn [r]
                    (testing "no token"
                      (is (= "invalid_request" (:error (answer r)))))))
     (signed-in opts "create" #(reset! a %))
     #(async/then (post token {"action" "revoke" "token" (:access_token @a)})
                  (fn [r]
                    (testing "section 7.1: action=revoke at the token endpoint, as earlier versions had it"
                      (is (= 200 (:status r))))))
     #(async/then (resource/token-info! (:access_token @a) opts)
                  (fn [i]
                    (is (nil? i)))))))

(deftest introspection
  (let [opts   (phase-2-opts (atom noon))
        h      (server/introspection-handler opts)
        a      (atom nil)
        at     (quot (inst-ms noon) 1000)
        remote (fn [routes]
                 {:introspection-endpoint "https://auth.example/introspect"
                  :resource-token         resource-token
                  :send                   (t/network routes)})]
    (run
     (signed-in opts "create" #(reset! a %))
     #(async/then (post h {"token" (:access_token @a)})
                  (fn [r]
                    (testing "S801 and S802: not without authorization, which says nothing"
                      (is (= 401 (:status r)))
                      (is (not (str/includes? (:body r) "active")))
                      (is (not (str/includes? (:body r) "user.example"))))))
     #(async/then (post h {"token" (:access_token @a)} "a wrong token")
                  (fn [r]
                    (is (= 401 (:status r)))))
     #(async/then (post h {"token" (:access_token @a)} resource-token)
                  (fn [r]
                    (testing "S803: an active token"
                      (is (= {:active    true
                              :me        "https://user.example/"
                              :client_id "https://app.example/"
                              :scope     "create"
                              :iat       at
                              :exp       (+ at 86400)}
                             (answer r))))))
     #(async/then (post h {"token" "made-up"} resource-token)
                  (fn [r]
                    (testing "S804: an invalid token, without more"
                      (is (= {:active false} (answer r))))))
     #(async/then (post h {"token" (:refresh_token @a)} resource-token)
                  (fn [r]
                    (testing "a refresh token isn't an active access token"
                      (is (= {:active false} (answer r))))))
     #(async/then (resource/access! (bearer (:access_token @a)) ["create"]
                                  (remote {"https://auth.example/introspect" h}))
                  (fn [info]
                    (testing "section 6: a resource server in another process"
                      (is (= {:me        "https://user.example/"
                              :client-id "https://app.example/"
                              :scope     "create"
                              :issued-at noon
                              :expires   (seconds-after noon 86400)}
                             info)))))
     #(async/then (resource/access! (bearer (:access_token @a)) ["create"] (remote {}))
                  (fn [a]
                    (testing "an introspection endpoint that fails"
                      (is (= 503 (get-in a [:response :status]))))))
     #(let [basic (server/introspection-handler
                   (assoc opts :introspect-pred (fn [r] (= "Basic cnM6cHc=" (get-in r [:headers "authorization"])))))]
        (async/then (basic {:request-method :post
                            :headers        {"authorization" "Basic cnM6cHc="}
                            :body           (url/query-string {"token" (:access_token @a)})})
                    (fn [r]
                      (testing "authorization by an :introspect-pred of your own"
                        (is (= true (:active (answer r)))))
                      (async/then (post basic {"token" (:access_token @a)} resource-token)
                                  (fn [r]
                                    (testing "in place of the resource tokens"
                                      (is (= 401 (:status r))))))))))))

(deftest legacy-verification
  (let [opts  (assoc (phase-2-opts (atom noon)) :legacy-verification? true)
        token (server/token-handler opts)
        a     (atom nil)]
    (run
     (signed-in opts "create update" #(reset! a %))
     #(async/then (token (bearer (:access_token @a)))
                  (fn [r]
                    (testing "the W3C Note, section 6.3.4: a GET verifies a token"
                      (is (= 200 (:status r)))
                      (is (= {:me "https://user.example/" :client_id "https://app.example/" :scope "create update"}
                             (answer r))))))
     #(async/then (token (bearer "made-up"))
                  (fn [r]
                    (testing "an invalid token"
                      (is (= 401 (:status r))))))
     #(async/then (token {:request-method :get :query-string (url/query-string (redemption "?code=c"))})
                  (fn [r]
                    (testing "S333: a GET without a token is still refused"
                      (is (= 401 (:status r))))))
     #(async/then ((server/token-handler (dissoc opts :legacy-verification?)) (bearer (:access_token @a)))
                  (fn [r]
                    (testing "and no GET at all by default"
                      (is (= 405 (:status r)))))))))

(deftest userinfo
  (let [opts (phase-2-opts (atom noon))
        h    (server/userinfo-handler opts)
        a    (atom nil)]
    (run
     (signed-in opts "profile email create" #(reset! a %))
     #(async/then (h (bearer (:access_token @a)))
                  (fn [r]
                    (testing "S701: the profile of the token response"
                      (is (= 200 (:status r)))
                      (is (= {:name "Ann" :url "https://user.example/" :email "ann@user.example"} (answer r)))
                      (is (= (:profile @a) (answer r))))))
     #(async/then (h {:request-method :get :headers {}})
                  (fn [r]
                    (testing "S702: not without a token"
                      (is (= 401 (:status r))))))
     #(async/then (h (bearer "made-up"))
                  (fn [r]
                    (testing "S703: not with an invalid token"
                      (is (= 401 (:status r)))
                      (is (= "invalid_token" (:error (answer r)))))))
     (signed-in opts "create" #(reset! a %))
     #(async/then (h (bearer (:access_token @a)))
                  (fn [r]
                    (testing "not without the profile scope"
                      (is (= 403 (:status r)))))))))
