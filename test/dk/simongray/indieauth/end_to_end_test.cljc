(ns dk.simongray.indieauth.end-to-end-test
  "A client and a server of this library, the one signing a user in at the
  other with a browser in between, as a site and an app would use them. On
  the JVM they talk over HTTP on localhost too."
  (:require #?(:clj [clojure.edn :as edn] :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.indieauth.server :as server]
            [dk.simongray.indieauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.url :as url]))

(def secret-text "a secret of thirty-two bytes, at least")

(defn- form-value
  "The value of the hidden input `k` in the HTML `s`."
  [s k]
  (second (re-find (re-pattern (str "name=\"" k "\" value=\"([^\"]*)\"")) s)))

(defn- consent-page
  "The page that asks the user, who is signed in already, to consent to the
  authorization `request`, by the `opts` of the server."
  [opts request]
  (let [c (server/consent request "https://user.example/" opts)]
    {:status  200
     :headers {"Content-Type" "text/html"}
     :body    (str "<p>" (get-in c [:client :client-name]) " asks for "
                   (str/join ", " (:scopes c))
                   "<form method=post action=/consent>"
                   "<input type=hidden name=\"token\" value=\"" (:token c) "\">")}))

(defn- site
  "The Ring handlers of the site of the user at https://user.example/,
  whose server is at https://auth.example/, with the network in the atom
  `net`, by URL."
  [net]
  (let [opts (atom nil)]
    (reset! opts {:issuer                 "https://auth.example/"
                  :authorization-endpoint "https://auth.example/auth"
                  :token-endpoint         "https://auth.example/token"
                  :revocation-endpoint    "https://auth.example/revoke"
                  :userinfo-endpoint      "https://auth.example/userinfo"
                  :secret                 secret-text
                  :scopes-supported       ["profile" "create"]
                  :codes                  (server/memory-store)
                  :tokens                 (server/memory-store)
                  :send                   #(@net %)
                  :authorize              #(consent-page @opts %2)})
    {"https://user.example/"
     (fn [_]
       ((t/page "<div class=h-card><a class='u-url p-name' href=/>Ann</a></div>"
                (server/link-header @opts))
        nil))

     "https://auth.example/.well-known/oauth-authorization-server"
     (server/metadata-handler @opts)

     "https://auth.example/auth"
     (server/handler @opts)

     "https://auth.example/consent"
     (fn [request]
       (let [token (get (into {} (ring/form-fields request 65536)) "token")]
         (async/then (server/profile! "https://user.example/" @opts)
                     (fn [profile]
                       (async/then (server/approve! token {:me "https://user.example/" :profile profile} @opts)
                                   (fn [{:keys [redirect error]}]
                                     (if redirect
                                       {:status 303 :headers {"Location" redirect} :body ""}
                                       {:status 400 :headers {} :body (:reason error)})))))))

     "https://auth.example/token"
     (server/token-handler @opts)

     "https://auth.example/revoke"
     (server/revocation-handler @opts)

     "https://auth.example/userinfo"
     (server/userinfo-handler @opts)

     "https://user.example/micropub"
     (fn [request]
       (async/then (server/access! request ["create"] @opts)
                   (fn [{:keys [error response me]}]
                     (if error
                       response
                       {:status 201 :headers {} :body (str "A post by " me)}))))}))

(defn- app
  "The Ring handlers of an app at https://app.example/ that signs its users
  in and keeps each session in the atom `sessions` by its state, or in the
  state itself, signed, when `secret` is given, with the network in the
  atom `net`, by URL. It keeps the session and the answer of each user
  who signed in in the atom `accounts`, by their me."
  [sessions accounts secret net]
  (let [opts   {:send #(@net %)}
        client (cond-> {:client-id    "https://app.example/"
                        :redirect-uri "https://app.example/callback"
                        :scope        "profile create"}
                 secret (assoc :secret secret))]
    {"https://app.example/"
     (indieauth/client-metadata-handler {:client-id "https://app.example/" :client-name "An app"})

     "https://app.example/login"
     (fn [{:keys [query-string]}]
       (async/then (indieauth/discover! (get (url/query-params query-string) "me") opts)
                   (fn [{:keys [error] :as discovery}]
                     (if error
                       {:status 400 :headers {} :body (:reason error)}
                       (let [{:keys [url session]} (indieauth/authorization-request discovery client)]
                         (when-not secret
                           (swap! sessions assoc (:state session) session))
                         {:status  302
                          :headers (cond-> {"Location" url}
                                     secret (assoc "Set-Cookie" (str "nonce=" (:nonce session)
                                                                     "; Path=/callback; HttpOnly; Secure; SameSite=Lax")))
                          :body    ""})))))

     "https://app.example/callback"
     (fn [{:keys [query-string headers]}]
       (let [params  (url/query-params query-string)
             state   (get params "state")
             nonce   (second (re-find #"(?:^|;\s*)nonce=([^;]*)" (str (get headers "cookie"))))
             session (if secret
                       (indieauth/state-session secret state nonce)
                       (get @sessions state))]
         (swap! sessions dissoc state)
         (async/then (indieauth/redeem! session params opts)
                     (fn [{:keys [error me] :as answer}]
                       (if error
                         {:status 400 :headers {} :body (str (:type error))}
                         (do (swap! accounts assoc me {:session session :answer answer})
                             {:status 200 :headers {} :body (pr-str answer)}))))))}))

(defn- post
  "A step that posts to the site's Micropub endpoint over the network in
  the atom `net` with the access token of the user in the atom
  `accounts`, and calls `f` with the response."
  [net accounts f]
  #(async/then (@net {:method  :post
                      :url     "https://user.example/micropub"
                      :headers {"Authorization" (str "Bearer " (get-in @accounts ["https://user.example/" :answer :access_token]))}
                      :body    "h=entry"})
               f))

(defn- sign-in
  "The steps of a user who signs in to the app at their own site, and posts
  with the token they get, over the network in the atom `net`, by the app
  that keeps its sessions in the atom `sessions` and its accounts in the
  atom `accounts`."
  [net sessions accounts]
  (let [page (atom nil)]
    [#(async/then (@net {:url "https://app.example/login?me=user.example"})
                  (fn [{:keys [status url body]}]
                    (testing "the app sends the browser to the server, which asks the user"
                      (is (= 200 status))
                      (is (str/starts-with? url "https://auth.example/auth?response_type=code&client_id="))
                      (is (str/starts-with? body "<p>An app asks for profile, create")))
                    (reset! page body)))
     #(async/then (@net {:method  :post
                         :url     "https://auth.example/consent"
                         :headers {"Content-Type" "application/x-www-form-urlencoded"}
                         :body    (url/query-string [["token" (form-value @page "token")]])})
                  (fn [{:keys [status url body]}]
                    (testing "the user says yes, and the browser goes back to the app"
                      (is (= 200 status) body)
                      (is (str/starts-with? url "https://app.example/callback?code=")))
                    (let [a (edn/read-string body)]
                      (testing "the app knows who the user is, and has a token"
                        (is (= "https://user.example/" (:me a)))
                        (is (= {:name "Ann" :url "https://user.example/"} (:profile a)))
                        (is (= "profile create" (:scope a)))))))
     (post net accounts
           (fn [{:keys [status body]}]
             (testing "the token works at the site's Micropub endpoint"
               (is (= 201 status))
               (is (= "A post by https://user.example/" body)))
             (is (empty? @sessions) "the session is used once")))]))

(defn- stay-signed-in
  "The steps of the app that refreshes the token of the user in the atom
  `accounts`, reads their profile information, and signs them out, over
  the network in the atom `net`."
  [net accounts]
  (let [account #(get @accounts "https://user.example/")
        opts    #(hash-map :send @net)]
    [#(let [{:keys [session answer]} (account)]
        (async/then (indieauth/refresh! session (:refresh_token answer) (opts))
                    (fn [a]
                      (testing "the app refreshes the token"
                        (is (= "https://user.example/" (:me a)))
                        (is (not= (:access_token answer) (:access_token a)))
                        (is (not= (:refresh_token answer) (:refresh_token a))))
                      (swap! accounts assoc-in ["https://user.example/" :answer] a))))
     (post net accounts
           (fn [{:keys [status]}]
             (testing "and the new token works"
               (is (= 201 status)))))
     #(let [{:keys [session answer]} (account)]
        (async/then (indieauth/userinfo! session (:access_token answer) (opts))
                    (fn [p]
                      (testing "the app reads the user's profile information"
                        (is (= {:name "Ann" :url "https://user.example/"} p))))))
     #(let [{:keys [session answer]} (account)]
        (async/then (indieauth/revoke! session (:refresh_token answer) (opts))
                    (fn [r]
                      (testing "the user signs out, and the app revokes the refresh token"
                        (is (= {:status 200} r))))))
     (post net accounts
           (fn [{:keys [status]}]
             (testing "which revokes the access token too"
               (is (= 401 status)))))]))

(defn- world
  "The routes of the site and of an app that signs its users in with
  `secret`, or with sessions of its own when it's nil, and the atoms of
  their network, of the app's sessions and of its accounts, as a vector."
  [secret]
  (let [net      (atom nil)
        sessions (atom {})
        accounts (atom {})]
    [(merge (site net) (app sessions accounts secret net)) net sessions accounts]))

(defn- steps
  "The steps of signing in, of staying signed in, and of signing out, over
  the network in the atom `net` of the world of the app's `sessions` and
  `accounts`."
  [net sessions accounts]
  (concat (sign-in net sessions accounts)
          (stay-signed-in net accounts)))

(deftest signing-in
  (apply run (for [secret [nil secret-text]
                   :let   [[routes net sessions accounts] (world secret)]
                   step   (do (reset! net (t/network routes))
                              (steps net sessions accounts))]
               step)))

#?(:clj
   (deftest signing-in-over-http
     (doseq [secret [nil secret-text]
             :let   [[routes net sessions accounts] (world secret)]]
       (t/on-localhost routes
                       (fn [proxied]
                         (reset! net (t/network proxied))
                         (apply run (steps net sessions accounts)))))))
