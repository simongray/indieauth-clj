(ns ^:no-doc dk.simongray.indieauth.fetch
  "The requests that a client sends and the answers it reads: pages and
  JSON documents that it gets, forms that it posts, and what goes wrong,
  as maps of the :error. The types of the errors are keywords of
  dk.simongray.indieauth, whose functions give them."
  (:require [dk.simongray.html-pieces :as html]
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

(defn page-nodes
  "The Hiccup of the HTML page in the `response`, or nil when it holds
  another kind of document."
  [{:keys [headers body] :as response}]
  (let [type (headers/media-type (headers/header headers "content-type"))]
    (when (and (string? body)
               (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (html/parse body))))
