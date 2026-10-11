(ns dk.simongray.indieauth.test-support
  "What the tests share: a test of steps that give promises in
  ClojureScript, a network of Ring handlers in memory that answers as the
  sites of the tests would, and on the JVM a server of Ring handlers on
  localhost."
  (:require [clojure.string :as str]
            #?(:cljs [clojure.test :refer [is async]])
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.json :as json]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            #?(:clj [dk.simongray.wary-fetch.headers :as headers])
            [dk.simongray.wary-fetch.url :as url])
  #?(:clj (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
                   [java.net InetSocketAddress]
                   [java.util.concurrent Executors])))

(defn run
  "Run the steps `fs` one after another as a test on either platform. Each
  step is a function of no arguments that gives a value or a promise.

  In ClojureScript, a deftest runs only the async test that it returns. So
  a deftest calls `run` once, as its last form, with all its steps."
  [& fs]
  #?(:clj  (doseq [f fs] (f))
     :cljs (async done
             (-> (reduce (fn [p f] (.then p (fn [_] (f)))) (js/Promise.resolve nil) fs)
                 (.catch (fn [e] (is false (str "rejected: " e))))
                 (.finally done)))))

(defn ring-request
  "The Ring request of the wary-fetch `request` map."
  [{:keys [method url headers body]}]
  (let [{:keys [scheme host port path query]} (indieauth/url-parts url)]
    {:request-method (or method :get)
     :scheme         (keyword scheme)
     :server-name    host
     :server-port    (if port (parse-long port) (if (= "https" scheme) 443 80))
     :uri            (if (empty? path) "/" path)
     :query-string   query
     :headers        (into {} (for [[k v] headers] [(str/lower-case (name k)) (str v)]))
     :body           body}))

(defn- fetched
  "The wary-fetch response from `url` of the Ring `response`."
  [url {:keys [status headers body]}]
  {:status  status
   :url     url
   :headers (into {} (for [[k v] headers] [(str/lower-case k) v]))
   :body    (if (string? body) body (some-> body str))})

(defn- without-query
  "The `url` without its query and fragment."
  [url]
  (first (str/split url #"[?#]" 2)))

(defn- host-of
  "The host and port of the `url`."
  [url]
  (:authority (indieauth/url-parts url)))

(defn- with-cookies
  "The `cookies`, a map of names to values, with those that the Set-Cookie
  value `v`, a text or texts, sets."
  [cookies v]
  (into (or cookies {})
        (for [s     (if (sequential? v) v [v])
              :let  [[_ k value] (re-find #"^\s*([^=;\s]+)=([^;]*)" (str s))]
              :when k]
          [k value])))

(defn- cookie-header
  "The Cookie header of the `cookies`, a map of names to values, or nil."
  [cookies]
  (some->> (seq cookies)
           (map (fn [[k v]] (str k "=" v)))
           (str/join "; ")))

(defn network
  "A function that sends a request map as http/send! does, to the Ring
  handler that `routes`, a map of URLs without their query, has for its
  URL, and else answers 404. It follows redirects as http/send! does,
  keeps the cookies of each host as a browser does, and conj's each
  request to the atom `log`, as the Ring request with its :url."
  ([routes]
   (network routes (atom [])))
  ([routes log]
   (let [jar (atom {})]
     (fn send [request]
       (let [request (http/revealed request)
             limit   (:max-redirects request 5)]
         (letfn [(step [request chain]
                   (let [host   (host-of (:url request))
                         cookie (cookie-header (get @jar host))
                         ring   (cond-> (assoc (ring-request request) :url (:url request))
                                  cookie (assoc-in [:headers "cookie"] cookie))
                         h      (get routes (without-query (:url request))
                                     (constantly {:status 404 :headers {} :body ""}))]
                     (swap! log conj ring)
                     (async/then
                      (h ring)
                      (fn [response]
                        (let [{:keys [status headers] :as r} (fetched (:url request) response)
                              location                       (get headers "location")]
                          (when-let [v (get headers "set-cookie")]
                            (swap! jar update host with-cookies v))
                          (if (and (#{301 302 303 307 308} status)
                                   location
                                   (< (count chain) limit))
                            (step (cond-> (assoc request :url (url/absolute-url (:url request) location))
                                    (= 303 status) (assoc :method :get :body nil))
                                  (conj chain [status (:url request) headers]))
                            (cond-> r
                              (seq chain) (assoc :redirects chain))))))))]
           (step request [])))))))

(defn page
  "A Ring handler that answers with the HTML `s`, and the Link header
  `link` when it's given."
  ([s]
   (page s nil))
  ([s link]
   (constantly {:status  200
                :headers (cond-> {"Content-Type" "text/html; charset=utf-8"}
                           link (assoc "Link" link))
                :body    s})))

(defn json-doc
  "A Ring handler that answers with the JSON of `x`, with the `status`,
  200 by default."
  ([x]
   (json-doc 200 x))
  ([status x]
   (constantly {:status  status
                :headers {"Content-Type" "application/json"}
                :body    (json/write-json x)})))

(defn redirect
  "A Ring handler that redirects with `status` to `url`."
  [status url]
  (constantly {:status status :headers {"Location" url} :body ""}))

(defn query
  "The query parameters of the `url`, as a map by name."
  [url]
  (url/query-params (second (re-find #"\?([^#]*)" url))))

#?(:clj
   (defn- exchange-request
     "The Ring request of the JDK server's `exchange`."
     [^HttpExchange exchange]
     (let [uri (.getRequestURI exchange)]
       {:request-method (keyword (str/lower-case (.getRequestMethod exchange)))
        :uri            (.getPath uri)
        :query-string   (.getRawQuery uri)
        :scheme         :http
        :headers        (into {}
                              (for [[k vs] (.getRequestHeaders exchange)]
                                [(str/lower-case k) (str/join ", " vs)]))
        :body           (.getRequestBody exchange)})))

#?(:clj
   (defn- respond!
     "Answer the JDK server's `exchange` with the Ring `response`."
     [^HttpExchange exchange {:keys [status headers body]}]
     (let [^bytes b (if (bytes? body) body (.getBytes (str body) "UTF-8"))]
       (doseq [[k v] headers]
         (.add (.getResponseHeaders exchange) (str k) (str v)))
       ;; with the request body open, Java 11 closes the connection after
       ;; an answer with no body, and the client reuses it
       (.close (.getRequestBody exchange))
       (if (zero? (alength b))
         (.sendResponseHeaders exchange status -1)
         (do (.sendResponseHeaders exchange status (alength b))
             (with-open [out (.getResponseBody exchange)]
               (.write out b))))
       (.close exchange))))

#?(:clj
   (defn with-server
     "Call `f` with the URL of a server on localhost that answers each
     request by the Ring handler that `handlers`, a map of paths, has for
     its path, or with 404."
     [handlers f]
     (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
       (.createContext server "/"
                       (reify HttpHandler
                         (handle [_ exchange]
                           (let [request (exchange-request exchange)
                                 h       (get handlers (:uri request))]
                             (respond! exchange
                                       (if h
                                         (h request)
                                         {:status 404 :headers {} :body ""}))))))
       ;; a thread for each exchange, since a handler can send a request
       ;; to the same server
       (.setExecutor server (Executors/newCachedThreadPool))
       (.start server)
       (try
         (f (str "http://127.0.0.1:" (.getPort (.getAddress server))))
         (finally
           (.stop server 0))))))

#?(:clj
   (defn- forwarder
     "A Ring handler that sends each request on over HTTP to the server at
     `base`, under the path of its `host`, and answers with its response."
     [base host]
     (fn [{:keys [request-method uri query-string body] :as request}]
       (let [r (http/send! {:method        request-method
                            :url           (str base "/" host uri
                                                (some->> query-string (str "?")))
                            :headers       (dissoc (:headers request) "host" "content-length")
                            :body          body
                            :max-redirects 0
                            :allow-pred    (constantly true)})]
         {:status  (:status r)
          :headers (into {} (for [k (keys (:headers r))]
                              [k (headers/joined (:headers r) k)]))
          :body    (:body r)}))))

#?(:clj
   (defn on-localhost
     "Call `f` with `routes`, a map of URLs to Ring handlers, whose handlers
     send each request over HTTP to a server on localhost that runs the
     handler of its URL. So the requests of a test go over real HTTP, with
     the URLs of the sites of the test."
     [routes f]
     (let [local (into {} (for [[u h] routes
                                :let  [{:keys [authority path]} (indieauth/url-parts u)]]
                            [(str "/" authority (if (empty? path) "/" path)) h]))]
       (with-server local
         (fn [base]
           (f (into {} (for [u (keys routes)]
                         [u (forwarder base (:authority (indieauth/url-parts u)))]))))))))
