(ns ^:no-doc dk.simongray.indieauth.fetch
  "The requests that a client sends and the answers it reads: pages and
  JSON documents that it gets, the links they name, forms that it posts,
  and what goes wrong, as maps of the :error. The types of the errors are
  keywords of dk.simongray.indieauth, whose functions give them."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth.ring :as ring]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

(defn failure
  "A map of the :error of `type`, a keyword, with the `reason` and the facts
  of the map `m`."
  ([type reason]
   (failure type reason {}))
  ([type reason m]
   {:error (merge {:type type :reason reason} m)}))

;; RFC 6749, section 5.2
(defn server-error
  "The :error of `type` for an answer of `status` with the JSON `m` of an
  OAuth 2.0 error, with its :code and its description when it has them."
  [type status m]
  (failure type
           (or (when (string? (:error_description m)) (:error_description m))
               (str "The server answered " status))
           (cond-> {:status status}
             (string? (:error m)) (assoc :code (:error m)))))

(defn get!
  "The response to a GET of `url` for the media types `accept`, with a body
  of `max-bytes` at most, by `opts`, or a map of the :error."
  [url accept max-bytes opts]
  (async/then (async/attempt
               #(http/fetch! url (assoc opts :accept accept :max-bytes max-bytes)))
              (fn [{{:keys [status] :as response} :value error :error}]
                (cond
                  error
                  {:error (http/failure error)}

                  (not (ring/success? status))
                  (failure :dk.simongray.indieauth/failed (str url " answered " status)
                           {:url url :status status})

                  :else
                  response))))

(defn exchange!
  "The response to the `request`, sent by the :send of `opts` without
  following a redirect, with a body of :max-json-bytes at most, or a map
  of the :error."
  [request {:keys [send max-json-bytes] :as opts}]
  (async/then (http/try-send! send request (assoc opts
                                                  :max-bytes max-json-bytes
                                                  :max-redirects 0))
              (fn [{:keys [value error]}]
                (or value {:error (http/failure error)}))))

(defn form-request
  "The request map that posts the form of `fields`, pairs of a name and a
  value, to `url` for a JSON answer. The body is a hidden text of
  wary-fetch, since it holds a code or a token."
  [url fields]
  {:method  :post
   :url     url
   :headers {"Content-Type" "application/x-www-form-urlencoded"
             "Accept"       "application/json"}
   :body    (secret/hide (url/query-string fields))})

(defn json-object
  "The map of the JSON object in the text `s`, with keyword keys in the
  names that the spec gives them, or nil when `s` holds another value or
  isn't JSON."
  [s]
  (let [x (json/read-json s)]
    (when (map? x)
      x)))

(defn page-html
  "The HTML of the page in the `response`, or nil when it holds another
  kind of document."
  [{:keys [headers body] :as response}]
  (let [type (headers/media-type (headers/header headers "content-type"))]
    (when (and (string? body)
               (contains? #{nil "text/html" "application/xhtml+xml"} type))
      body)))

;; RFC 8288, section 3.3; HTML Standard, section 4.6.1: link types
;; separated by whitespace, in any case
(defn- link
  "The link of `rel`, a text of link types, to `href`, as a map of its
  :rels, a set of link types in lower case, and its :href, or nil without
  an href."
  [rel href]
  (when href
    {:rels (set (str/split (str/lower-case (str rel)) #"\s+"))
     :href href}))

;; IndieAuth 4.1 and 4.2.2; RFC 8288, section 3
(defn links
  "The links of the `response` and of its `page`, its HTML or Hiccup, by
  `opts`, as maps of :rels and an absolute :href: those of its Link
  headers first, and then those of the page's link elements.

  Those are in its head, or in all of it by :body-links?. The head alone
  is read, base element and all, since anyone who writes in the body
  could add a base element or a link there."
  [{:keys [url headers] :as response} page {:keys [body-links?] :as opts}]
  (concat
   (keep (fn [{:keys [rel href]}] (link rel (url/absolute-url url href)))
         (headers/links headers))
   (when page
     (keep (fn [[_ {:keys [rel href]}]] (link rel href))
           (html/links (if body-links? page (html/head page))
                       {:base-url url :link-tags #{:link}})))))

(defn hrefs
  "The hrefs of the `links` with the link type `rel`, in their order, each
  where it first appears."
  [rel links]
  (let [rel (str/lower-case rel)]
    (distinct (keep #(when (contains? (:rels %) rel) (:href %)) links))))
