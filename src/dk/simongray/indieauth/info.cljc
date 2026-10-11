(ns ^:no-doc dk.simongray.indieauth.info
  "What a page says of a client or a user: the client information of a
  client metadata document or of an h-app, and the profile information of
  a user's representative h-card."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.links :as links]
            [dk.simongray.microformats :as mf]
            [dk.simongray.wary-fetch.url :as url]))

(defn unknown-client
  "The client information of the `client-id` alone."
  [client-id]
  {:client-id client-id :redirect-uris []})

(defn- property
  "The first value of the property `k` of the microformat `item`, the URL
  of an image with alt text too, or nil."
  [item k]
  (let [v (first (get-in item [:properties k]))]
    (cond
      (string? v) v
      (map? v)    (when (string? (:value v)) (:value v)))))

;; IndieAuth 4.2.1 and its note on h-app
(defn app-info
  "The client information in the HTML page of the `response` from
  `client-id`: its first h-app, and its redirect URLs, from its Link
  headers and the link elements in its head, as section 4.2.2 names them."
  [client-id {:keys [url body] :as response}]
  (let [nodes (html/parse body)
        apps  (->> (:items (mf/parse nodes url))
                   (mapcat #(tree-seq map? :children %))
                   (filter #(some #{"h-app" "h-x-app"} (:type %))))
        app   (or (first (filter #(= client-id (some-> (property % :url) indieauth/canonical-url))
                                 apps))
                  (first apps))]
    (cond-> (assoc (unknown-client client-id)
                   :redirect-uris (vec (links/hrefs "redirect_uri" (links/links response nodes {}))))
      (property app :name) (assoc :client-name (property app :name))
      (property app :url)  (assoc :client-uri (property app :url))
      (property app :logo) (assoc :logo-uri (property app :logo)))))

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

;; https://microformats.org/wiki/representative-h-card-parsing
(defn- representative-card
  "The representative h-card of the page at `url` whose microformats are
  `mf2`, or nil."
  [mf2 url]
  (let [cards (filter #(some #{"h-card"} (:type %)) (:items mf2))
        urls  #(set (keep indieauth/canonical-url (get-in % [:properties :url])))
        uids  #(set (keep indieauth/canonical-url (get-in % [:properties :uid])))
        me    (set (keep indieauth/canonical-url (get-in mf2 [:rels :me])))
        page  (indieauth/canonical-url url)]
    (or (first (filter #(and ((uids %) page) ((urls %) page)) cards))
        (first (filter #(some me (urls %)) cards))
        (when (= 1 (count cards))
          (first (filter #((urls %) page) cards))))))

;; IndieAuth 5.3.4
(defn page-profile
  "The :name, :url, :photo and :email of the representative h-card of the
  HTML text `body` of the page at `url`, those it has, or nil."
  [body url]
  (let [card (representative-card (mf/parse body url) url)]
    (not-empty
     (into {}
           (filter (fn [[_ v]] (and (string? v) (seq v))))
           {:name  (property card :name)
            :url   (property card :url)
            :photo (property card :photo)
            :email (some-> (property card :email) (str/replace #"(?i)^mailto:" ""))}))))
