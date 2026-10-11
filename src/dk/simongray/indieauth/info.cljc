(ns ^:no-doc dk.simongray.indieauth.info
  "What a page says of a client or a user: the client information of a
  client metadata document or of an h-app, and the profile information of
  a user's representative h-card."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.fetch :as fetch]
            [dk.simongray.microformats :as mf]
            [dk.simongray.wary-fetch.url :as url]))

(defn unknown-client
  "The client information of the `client-id` alone."
  [client-id]
  {:client-id client-id :redirect-uris []})

;; IndieAuth 4.2.1 and its note on h-app
(defn app-info
  "The client information in the HTML page of the `response` from
  `client-id`: its first h-app, and its redirect URLs, from its Link
  headers and the link elements in its head, as section 4.2.2 names them."
  [client-id {:keys [url body] :as response}]
  (let [nodes (html/parse body)
        apps  (filter #(some #{"h-app" "h-x-app"} (:type %)) (mf/items (mf/parse nodes url)))
        app   (or (first (filter #(= client-id (some-> (mf/property % :url) indieauth/canonical-url))
                                 apps))
                  (first apps))]
    (cond-> (assoc (unknown-client client-id)
                   :redirect-uris (vec (fetch/hrefs "redirect_uri" (fetch/links response nodes {}))))
      (mf/property app :name) (assoc :client-name (mf/property app :name))
      (mf/property app :url)  (assoc :client-uri (mf/property app :url))
      (mf/property app :logo) (assoc :logo-uri (mf/property app :logo)))))

;; IndieAuth 4.2.1; OAuth Client ID Metadata Document
(defn document-info
  "The client information in the client metadata document `m` from
  `client-id`, or nil when the document names another client, which
  section 4.2.1 says not to trust."
  [client-id {:keys [client_name client_uri logo_uri redirect_uris] :as m}]
  (when (= client-id (some-> (:client_id m) str indieauth/canonical-url))
    (let [text? #(and (string? %) (seq %))]
      (cond-> (assoc (unknown-client client-id)
                     :redirect-uris (filterv string? (when (sequential? redirect_uris)
                                                       redirect_uris)))
        (text? client_name)     (assoc :client-name client_name)
        ;; the page about a client is a prefix of its identifier
        (and (text? client_uri)
             (str/starts-with? client-id client_uri))
        (assoc :client-uri client_uri)
        (url/web-url? logo_uri) (assoc :logo-uri logo_uri)))))

;; IndieAuth 5.3.4
(defn page-profile
  "The :name, :url, :photo and :email of the representative h-card of the
  HTML text `body` of the page at `url`, those it has, or nil."
  [body url]
  (let [card (mf/representative-card (mf/parse body url) url)]
    (not-empty
     (into {}
           (filter (fn [[_ v]] (and (string? v) (seq v))))
           {:name  (mf/property card :name)
            :url   (mf/property card :url)
            :photo (mf/property card :photo)
            :email (some-> (mf/property card :email) (str/replace #"(?i)^mailto:" ""))}))))
