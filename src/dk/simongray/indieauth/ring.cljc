(ns ^:no-doc dk.simongray.indieauth.ring
  "The Ring requests that the endpoints take, and the answers they give."
  (:require [clojure.string :as str]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.url :as url])
  #?(:clj (:import [java.io InputStream])))

(defn body-bytes
  "The bytes of the `body` of a Ring request, which is a string, bytes, a
  stream or nothing, or nil when it holds more than `max-bytes`. In
  ClojureScript a stream gives nil too, so a server there reads the body
  first."
  [body max-bytes]
  (let [b (cond
            (nil? body)
            (bytes/encode "")

            (string? body)
            (bytes/encode body)

            :else
            #?(:clj  (if (bytes? body)
                       body
                       (.readNBytes ^InputStream body (int (inc max-bytes))))
               :cljs (when (instance? js/Uint8Array body) body)))]
    (when (and b (<= (bytes/length b) max-bytes))
      b)))

;; URL Standard, section 5.1
(defn fields
  "The fields of the form or query `s` in application/x-www-form-urlencoded,
  as pairs of a name and a value."
  [s]
  (let [decode #(url/percent-decode (str/replace % "+" " "))]
    (for [part  (str/split (str s) #"&")
          :when (seq part)
          :let  [[k v] (str/split part #"=" 2)]]
      [(decode k) (decode (or v ""))])))

(defn- param-fields
  "The fields of the Ring `params` map, whose values are texts or vectors
  of them, as pairs of a name and a value."
  [params]
  (for [[k v] params
        v     (if (sequential? v) v [v])]
    [(name k) v]))

(defn query-fields
  "The fields of the query of the Ring `request`, as pairs of a name and a
  value, from its :query-string or else its :query-params."
  [{:keys [query-string query-params] :as request}]
  (if query-string
    (fields query-string)
    (param-fields query-params)))

(defn form-fields
  "The fields of the form that the Ring `request` posts, as pairs of a name
  and a value, from its :form-params or else from a body of `max-bytes` at
  most. Nil when the body is larger."
  [{:keys [form-params body] :as request} max-bytes]
  (if (seq form-params)
    (param-fields form-params)
    (some-> (body-bytes body max-bytes) bytes/decode fields)))

;; RFC 6749, section 3.1: a parameter comes once
(defn single-values
  "The fields `pairs` as a map of each name to its value, and of each name
  that comes more than once to ::repeated."
  [pairs]
  (reduce (fn [m [k v]]
            (assoc m k (if (contains? m k) ::repeated v)))
          {}
          pairs))

(defn header
  "The value of the header `header-name` of the Ring `request`, whose
  header names are in lower case."
  [request header-name]
  (get-in request [:headers (str/lower-case header-name)]))

(def cors-headers
  "The headers that let a page on any origin read an answer that holds no
  credentials of the browser's own, e.g. that of a client in a browser."
  {"Access-Control-Allow-Origin"  "*"
   "Access-Control-Allow-Methods" "GET, HEAD, POST, OPTIONS"
   "Access-Control-Allow-Headers" "Authorization, Content-Type"})

(defn response
  "The Ring response of `status` with the text `body` of `media-type`, which
  a browser takes as it is rather than sniffing for another."
  [status media-type body]
  {:status  status
   :headers {"Content-Type"           media-type
             "X-Content-Type-Options" "nosniff"}
   :body    body})

(defn text-response
  "The Ring response of `status` with the plain text `s`."
  [status s]
  (response status "text/plain; charset=utf-8" s))

;; RFC 6749, section 5.1: a response with a token or a code is not cached
(defn json-response
  "The Ring response of `status` with the JSON of `x`, which no cache keeps."
  [status x]
  (update (response status "application/json" (json/write-json x))
          :headers merge {"Cache-Control" "no-store"
                          "Pragma"        "no-cache"}))

;; RFC 9110, section 15.5.6
(defn not-allowed
  "The Ring response to a request whose method isn't one of `methods`."
  [methods]
  (assoc-in (text-response 405 "") [:headers "Allow"] (str/join ", " methods)))

(defn with-cors
  "The Ring `response` with cors-headers."
  [response]
  (update response :headers merge cors-headers))

(defn handler
  "A Ring handler that answers by the function `f` of a request, which gives
  a response or a promise of one, and that takes the arguments of a
  synchronous and of an asynchronous handler."
  [f]
  (fn
    ([request]
     (f request))
    ([request respond raise]
     #?(:clj  (let [{:keys [answer error]} (try
                                             {:answer (async/then (f request) identity)}
                                             (catch Throwable e
                                               {:error e}))]
                (if error
                  (raise error)
                  (respond answer)))
        :cljs (-> (js/Promise.resolve nil)
                  (.then (fn [_] (f request)))
                  (.then respond)
                  (.catch raise))))))
