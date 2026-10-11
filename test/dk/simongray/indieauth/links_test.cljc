(ns dk.simongray.indieauth.links-test
  "The links of a response by their relation types, from its Link headers
  and the head of its page."
  (:require [clojure.test :refer [deftest is testing]]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth.links :as links]))

(defn- urls
  "The URLs of `rel` in a response from `url` with the `link` header and
  the HTML `s`, by `opts`."
  ([url link s]
   (urls url link s {}))
  ([url link s opts]
   (links/hrefs "indieauth-metadata"
                (links/links {:url url :headers (if link {"link" link} {})}
                             (html/parse s)
                             opts))))

(deftest hrefs
  (testing "the Link headers first, then the link elements, each in order"
    (is (= ["https://a.example/1" "https://b.example/2" "https://a.example/3"]
           (urls "https://a.example/p"
                 "</1>; rel=\"indieauth-metadata\", <https://b.example/2>; rel=indieauth-metadata"
                 "<link rel=indieauth-metadata href=/3>"))))
  (testing "against the base of the page and the URL of the response"
    (is (= ["https://a.example/x/meta?a=1&b=2"]
           (urls "https://a.example/p" nil "<head><base href=/x/><link rel=indieauth-metadata href='meta?a=1&amp;b=2'>")))
    (is (= ["https://a.example/meta"]
           (urls "https://a.example/p" nil "<head><link rel=indieauth-metadata href=/meta></head><body><base href=https://decoy.example/>"))
        "a base in the body doesn't count"))
  (testing "one of several relation types, in any case"
    (is (= ["https://a.example/m"] (urls "https://a.example/" nil "<link rel='me IndieAuth-Metadata' href=m>"))))
  (testing "the head alone"
    (let [s "<html><head><link rel=indieauth-metadata href=/head></head><body><link rel=indieauth-metadata href=https://decoy.example/></body>"]
      (is (= ["https://a.example/head"] (urls "https://a.example/" nil s)))
      (is (= ["https://a.example/head" "https://decoy.example/"] (urls "https://a.example/" nil s {:body-links? true}))
          "unless :body-links?"))
    (is (= ["https://a.example/m"] (urls "https://a.example/" nil "<title>x</title><link rel=indieauth-metadata href=m><p>hi<link rel=indieauth-metadata href=n>"))
        "a page without a head tag"))
  (testing "not an a element, a comment or a script"
    (is (empty? (urls "https://a.example/" nil (str "<head><!-- <link rel=indieauth-metadata href=c> -->"
                                                    "<script>'<link rel=indieauth-metadata href=s>'</script></head>"
                                                    "<body><a rel=indieauth-metadata href=a>a</a>"))))))
