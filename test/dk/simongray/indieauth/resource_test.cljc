(ns dk.simongray.indieauth.resource-test
  "The checks of an access token that a resource server makes, in the
  store of a server in the same process, and at introspection endpoints
  that misbehave. Those at the library's own introspection endpoint are in
  the server's tests."
  (:require [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth.digest :as digest]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.server :as server]
            [dk.simongray.indieauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.json :as json]))

(def noon #inst "2026-10-11T12:00:00Z")

(def info
  {:me        "https://user.example/"
   :client-id "https://app.example/"
   :scope     "create update"
   :issued-at noon
   :expires   #inst "2026-10-11T13:00:00Z"})

(deftest bearer-tokens
  (testing "RFC 6750, sections 2.1 and 2.2"
    (is (= "the-token" (resource/bearer-token {:headers {"authorization" "Bearer the-token"}})))
    (is (= "the-token" (resource/bearer-token {:headers {"authorization" "bearer  the-token "}})))
    (is (= "the-token" (resource/bearer-token {:form-params {"access_token" "the-token"}})))
    (is (nil? (resource/bearer-token {:headers {"authorization" "Basic abc"}})))))

(deftest access-problems
  (testing "section 8.1"
    (is (nil? (resource/access-problem info ["create"])))
    (is (nil? (resource/access-problem info [])))
    (is (= {:status 403 :code "insufficient_scope" :scope "delete"}
           (dissoc (resource/access-problem info ["delete"]) :reason)))
    (is (= 401 (:status (resource/access-problem nil ["create"])))))
  (testing "RFC 6750, section 3"
    (let [r (resource/problem-response (resource/access-problem info ["delete"]))]
      (is (= "Bearer error=\"insufficient_scope\", scope=\"delete\"" (get-in r [:headers "WWW-Authenticate"])))
      (is (= "insufficient_scope" (:error (json/read-json (:body r))))))))

(deftest access
  (let [clock  (atom noon)
        tokens (server/memory-store (atom {}) #(deref clock))
        opts   {:tokens tokens :now-fn #(deref clock)}
        ask    #(resource/access! {:headers (if % {"authorization" (str "Bearer " %)} {})}
                                  ["create"] opts)]
    ((:put! tokens) (digest/text "the-token") (assoc info :type :access))
    ((:put! tokens) (digest/text "a-refresh-token") (assoc info :type :refresh))
    (run
     #(async/then (ask "the-token")
                  (fn [a]
                    (testing "a token that grants the scope"
                      (is (= info a)))))
     #(async/then (ask "made-up")
                  (fn [a]
                    (testing "an unknown token"
                      (is (= 401 (get-in a [:response :status])))
                      (is (= "invalid_token" (get-in a [:error :code]))))))
     #(async/then (ask "a-refresh-token")
                  (fn [a]
                    (testing "a refresh token is no access token"
                      (is (= "invalid_token" (get-in a [:error :code]))))))
     #(async/then (ask nil)
                  (fn [a]
                    (testing "no token, and an answer that says no more"
                      (is (= 401 (get-in a [:response :status])))
                      (is (= "Bearer" (get-in a [:response :headers "WWW-Authenticate"]))))))
     #(do (reset! clock #inst "2026-10-11T13:00:00Z")
          (async/then (resource/token-info! "the-token" opts)
                      (fn [i]
                        (testing "an expired token"
                          (is (nil? i)))))))))

(defn- endpoint-opts
  "The options of a resource server whose introspection endpoint answers
  by the Ring handler `h`."
  [h]
  {:introspection-endpoint "https://auth.example/introspect"
   :resource-token         "the-token-of-a-resource-server"
   :send                   (t/network {"https://auth.example/introspect" h})})

(deftest introspection-answers
  (let [at  (quot (inst-ms noon) 1000)
        ask #(resource/access! {:headers {"authorization" "Bearer the-token"}} ["create"] %)]
    (run
     #(async/then (resource/introspect! "the-token"
                                        (endpoint-opts (t/json-doc {:active    "true"
                                                                    :me        "https://user.example/"
                                                                    :client_id "https://app.example/"
                                                                    :scope     "create update"
                                                                    :iat       (str at)
                                                                    :exp       (str (+ at 3600))})))
                  (fn [i]
                    (testing "section 6.2: true and numbers as texts, as its example writes them"
                      (is (= info i)))))
     #(async/then (resource/introspect! "the-token" (endpoint-opts (t/json-doc {:active true})))
                  (fn [i]
                    (testing "an active token without a me"
                      (is (nil? i)))))
     #(async/then (ask (endpoint-opts (t/page "<p>Hi")))
                  (fn [a]
                    (testing "an answer that isn't JSON"
                      (is (= 503 (get-in a [:response :status]))))))
     #(async/then (ask (assoc (endpoint-opts nil) :send (fn [_] (throw (ex-info "Connection refused" {})))))
                  (fn [a]
                    (testing "an endpoint that can't be reached"
                      (is (= 503 (get-in a [:response :status])))))))))
