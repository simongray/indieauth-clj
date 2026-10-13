(ns ^:no-doc dk.simongray.indieauth.ring
  "The Ring requests that the endpoints take, and the answers they give."
  (:require [clojure.string :as str]
            #?(:clj [dk.simongray.wary-fetch.async :as async])
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.url :as url]
            [dk.simongray.webcrypto.bytes :as bytes])
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

(defn param-fields
  "The fields of the Ring `params` map, whose keys are texts or keywords
  and whose values are texts or vectors of them, as pairs of a name and a
  value."
  [params]
  (for [[k v] params
        v     (if (sequential? v) v [v])]
    [(name k) v]))

(defn query-fields
  "The fields of the query of the Ring `request`, as pairs of a name and a
  value, from its :query-string or else its :query-params."
  [{:keys [query-string query-params] :as request}]
  (if query-string
    (url/query-pairs query-string)
    (param-fields query-params)))

(defn form-fields
  "The fields of the form that the Ring `request` posts, as pairs of a name
  and a value, from its :form-params or else from a body of `max-bytes` at
  most. Nil when the body is larger."
  [{:keys [form-params body] :as request} max-bytes]
  (if (seq form-params)
    (param-fields form-params)
    (some-> (body-bytes body max-bytes) bytes/decode url/query-pairs)))

(defn param
  "The value of the parameter `k`, a text, in `params`, a map whose keys
  are texts or keywords, and the first when it has several."
  [params k]
  (let [v (get params k (get params (keyword k)))]
    (if (sequential? v) (first v) v)))

;; RFC 6749, section 3.1: a parameter comes once
(defn single-values
  "The fields `pairs` as a map of each name to its value, and of each name
  that comes more than once to ::repeated."
  [pairs]
  (reduce (fn [m [k v]]
            (assoc m k (if (contains? m k) ::repeated v)))
          {}
          pairs))

(defn success?
  "Whether the `status` of a response is that of a success."
  [status]
  (and (int? status) (<= 200 status 299)))

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

(defn with-cors
  "The Ring `response` with cors-headers, unless `cors?` is false."
  ([response]
   (with-cors response true))
  ([response cors?]
   (cond-> response
     cors? (update :headers merge cors-headers))))

(def preflight
  "The Ring response to the preflight request of a page in a browser."
  (with-cors (text-response 204 "")))

;; RFC 9110, section 15.5.6
(defn- by-method
  "A function of a Ring request that answers it by the function of its
  method in `fns`, or with 405 and the methods of `fns`."
  [fns]
  (let [allow (->> (keys fns) (map (comp str/upper-case name)) sort (str/join ", "))]
    (fn [{:keys [request-method] :as request}]
      (if-let [f (get fns request-method)]
        (f request)
        (assoc-in (text-response 405 "") [:headers "Allow"] allow)))))

(defn handler
  "A Ring handler that answers a request by the function of its method in
  `fns`, a map of request methods to functions of a request, which give a
  response or a promise of one. Another method gets 405. It takes the
  arguments of a synchronous and of an asynchronous handler."
  [fns]
  (let [f (by-method fns)]
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
                    (.catch raise)))))))
