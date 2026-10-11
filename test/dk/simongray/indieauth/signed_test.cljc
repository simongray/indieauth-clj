(ns dk.simongray.indieauth.signed-test
  "The signed maps that make a round trip through a browser."
  (:require [clojure.test :refer [deftest is testing]]
            [dk.simongray.indieauth.signed :as signed]
            [dk.simongray.wary-fetch.secret :as secret]))

(def secret-text "0123456789abcdef0123456789abcdef")
(def noon #inst "2026-10-11T12:00:00Z")
(def later #inst "2026-10-11T12:05:00Z")

(deftest signed-maps
  (let [m {:me "https://user.example.net/" :scope #{"profile"}}
        s (signed/sign secret-text :state m noon)]
    (is (re-matches #"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" s) "URL-safe")
    (is (= m (signed/unsign secret-text :state s later 600)))
    (is (= m (signed/unsign (secret/hide secret-text) :state s later 600)) "with a hidden secret")
    (testing "nil for"
      (is (nil? (signed/unsign secret-text :state s #inst "2026-10-11T12:10:01Z" 600)) "an old one")
      (is (nil? (signed/unsign secret-text :state s #inst "2026-10-11T11:59:59Z" 600)) "one from the future")
      (is (nil? (signed/unsign secret-text :consent s later 600)) "another kind")
      (is (nil? (signed/unsign (str secret-text "!") :state s later 600)) "another secret")
      (is (nil? (signed/unsign secret-text :state (str s "x") later 600)) "a changed one")
      (is (nil? (signed/unsign secret-text :state (str "e" (subs s 1)) later 600)) "a changed payload")
      (doseq [x [nil "" "." "a.b" 42]]
        (is (nil? (signed/unsign secret-text :state x later 600)) (pr-str x)))))
  (testing "a secret of fewer than 32 bytes"
    (is (thrown? #?(:clj Exception :cljs :default) (signed/sign "short" :state {} noon))))
  (testing "now, by default"
    (let [s (signed/sign secret-text :comment {:path "/a-post"})]
      (is (= {:path "/a-post"} (signed/unsign secret-text :comment s 1800)))
      (is (nil? (signed/unsign secret-text :state s 1800)) "of another kind")))
  (testing "a text derived from another"
    (is (= (signed/derive-text secret-text "code_verifier" "a")
           (signed/derive-text secret-text "code_verifier" "a")))
    (is (not= (signed/derive-text secret-text "code_verifier" "a")
              (signed/derive-text secret-text "code_verifier" "b")))
    (is (not= (signed/derive-text secret-text "code_verifier" "a")
              (signed/derive-text secret-text "other" "a")))))
