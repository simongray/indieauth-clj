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
  atom `net`, by URL."
  [sessions secret net]
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
                     (fn [{:keys [error] :as answer}]
                       (if error
                         {:status 400 :headers {} :body (str (:type error))}
                         {:status 200 :headers {} :body (pr-str answer)})))))}))

(defn- sign-in
  "The steps of a user who signs in to the app at their own site, and posts
  with the token they get, over the network in the atom `net`, by the app
  that keeps its sessions in the atom `sessions`."
  [net sessions]
  (let [page   (atom nil)
        answer (atom nil)]
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
                        (is (= "profile create" (:scope a))))
                      (reset! answer a))))
     #(async/then (@net {:method  :post
                         :url     "https://user.example/micropub"
                         :headers {"Authorization" (str "Bearer " (:access_token @answer))}
                         :body    "h=entry"})
                  (fn [{:keys [status body]}]
                    (testing "the token works at the site's Micropub endpoint"
                      (is (= 201 status))
                      (is (= "A post by https://user.example/" body)))
                    (is (empty? @sessions) "the session is used once")))]))

(defn- world
  "The routes of the site and of an app that signs its users in with
  `secret`, or with sessions of its own when it's nil, and the atoms of
  their network and of the app's sessions, as a vector."
  [secret]
  (let [net      (atom nil)
        sessions (atom {})]
    [(merge (site net) (app sessions secret net)) net sessions]))

(deftest signing-in
  (apply run (for [secret [nil secret-text]
                   :let   [[routes net sessions] (world secret)]
                   step   (do (reset! net (t/network routes))
                              (sign-in net sessions))]
               step)))

#?(:clj
   (deftest signing-in-over-http
     (doseq [secret [nil secret-text]
             :let   [[routes net sessions] (world secret)]]
       (t/on-localhost routes
                       (fn [proxied]
                         (reset! net (t/network proxied))
                         (apply run (sign-in net sessions)))))))
