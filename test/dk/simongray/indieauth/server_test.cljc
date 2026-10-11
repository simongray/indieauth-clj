(ns dk.simongray.indieauth.server-test
  "The server: its metadata, the authorization request, consent and codes,
  the token endpoint, the stores, client information, profile information
  and the checks of a resource server. A case of indieauth.rocks's server
  tests is named by its number, with clients of the test's own."
  (:require #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.server :as server]
            [dk.simongray.indieauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
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
              :grant_types_supported                          ["authorization_code"]
              :code_challenge_methods_supported               ["S256"]
              :authorization_response_iss_parameter_supported true}
             m)))
    (testing "S104 and S114: JSON that a page can read"
      (let [r ((server/metadata-handler opts) {:request-method :get})]
        (is (= 200 (:status r)))
        (is (= "application/json" (get-in r [:headers "Content-Type"])))
        (is (= "*" (get-in r [:headers "Access-Control-Allow-Origin"])))
        (is (= m (json/read-object (:body r))))))
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
  (json/read-object (:body response)))

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
                             (dissoc a :access_token))
                          "S409: the profile that the scopes grant, of texts"))
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
     #(async/then (token {:request-method :get :query-string (url/query-string (redemption "?code=c"))})
                  (fn [r]
                    (testing "S333: not a GET"
                      (is (= 405 (:status r)))
                      (is (= "POST, OPTIONS" (get-in r [:headers "Allow"]))))))
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
                                        (answer r)))))))))))

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
  (testing "a store keeps the hash of a code or a token, not the text"
    (is (= "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564" (server/hash-key "foo")))))

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
                        (is (empty? @log)))))))))

(deftest profiles
  (is (nil? (server/profile {:url "https://user.example/" :body "<p class=h-card><a class=u-url href=https://other.example/>B</a>"}))
      "an h-card of another page")
  (run
   #(async/then (server/profile! "https://user.example/" {:send (t/network clients)})
                (fn [p]
                  (testing "the representative h-card"
                    (is (= {:name  "Ann"
                            :url   "https://user.example/"
                            :photo "https://user.example/ann.jpg"
                            :email "ann@user.example"}
                           p)))))))

(deftest resource-servers
  (let [clock (atom noon)
        opts  {:tokens (server/memory-store (atom {}) #(deref clock)) :now-fn #(deref clock)}
        info  {:me "https://user.example/" :client-id "https://app.example/" :scope "create update"
               :issued-at noon :expires #inst "2026-10-11T13:00:00Z"}]
    ((:put! (:tokens opts)) (server/hash-key "the-token") info)
    (testing "RFC 6750: the token of a request"
      (is (= "the-token" (server/bearer-token {:headers {"authorization" "Bearer the-token"}})))
      (is (= "the-token" (server/bearer-token {:headers {"authorization" "bearer  the-token "}})))
      (is (= "the-token" (server/bearer-token {:form-params {"access_token" "the-token"}})))
      (is (nil? (server/bearer-token {:headers {"authorization" "Basic abc"}}))))
    (testing "section 8.1"
      (is (nil? (server/access-problem info ["create"])))
      (is (nil? (server/access-problem info [])))
      (is (= {:status 403 :code "insufficient_scope" :scope "delete"}
             (dissoc (server/access-problem info ["delete"]) :reason)))
      (is (= 401 (:status (server/access-problem nil ["create"])))))
    (let [r (server/problem-response (server/access-problem info ["delete"]))]
      (is (= "Bearer error=\"insufficient_scope\", scope=\"delete\"" (get-in r [:headers "WWW-Authenticate"])))
      (is (= "insufficient_scope" (:error (answer r)))))
    (run
     #(async/then (server/access! {:headers {"authorization" "Bearer the-token"}} ["create"] opts)
                  (fn [a]
                    (testing "a token that grants the scope"
                      (is (= info a)))))
     #(async/then (server/access! {:headers {"authorization" "Bearer made-up"}} ["create"] opts)
                  (fn [a]
                    (testing "an unknown token"
                      (is (= 401 (get-in a [:response :status])))
                      (is (= "invalid_token" (get-in a [:error :code]))))))
     #(async/then (server/access! {:headers {}} ["create"] opts)
                  (fn [a]
                    (testing "no token, and an answer that says no more"
                      (is (= 401 (get-in a [:response :status])))
                      (is (= "Bearer" (get-in a [:response :headers "WWW-Authenticate"]))))))
     #(do (reset! clock #inst "2026-10-11T13:00:00Z")
          (async/then (server/token-info! "the-token" opts)
                      (fn [i]
                        (testing "an expired token"
                          (is (nil? i)))))))))
