(ns dk.simongray.indieauth.resource-test
  "The checks of an access token that a resource server makes, in the
  store of a server in the same process. Those at an introspection
  endpoint are in the server's tests."
  (:require [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.indieauth.resource :as resource]
            [dk.simongray.indieauth.server :as server]
            [dk.simongray.indieauth.test-support :refer [run]]
            [dk.simongray.wary-fetch.async :as async]))

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
      (is (= "insufficient_scope" (:error (json/read-object (:body r))))))))

(deftest access
  (let [clock  (atom noon)
        tokens (server/memory-store (atom {}) #(deref clock))
        opts   {:tokens tokens :now-fn #(deref clock)}
        ask    #(resource/access! {:headers (if % {"authorization" (str "Bearer " %)} {})}
                                  ["create"] opts)]
    ((:put! tokens) (bytes/hash-text "the-token") (assoc info :type :access))
    ((:put! tokens) (bytes/hash-text "a-refresh-token") (assoc info :type :refresh))
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
