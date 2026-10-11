(ns ^:no-doc dk.simongray.indieauth.links
  "The links that a response names by their relation types: those of its
  Link headers, and those of the link elements in the head of an HTML page.
  IndieAuth finds its servers and a client's redirect URLs this way, as do
  Webmention, Micropub and WebSub, so nothing here is IndieAuth's own.

  The page is Hiccup that html-pieces parsed, so that it's parsed once for
  its links and its microformats."
  (:require [clojure.string :as str]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.url :as url]))

(def head-tags
  "The elements that a browser puts in the head of a page until the body
  begins, even in a page without a head tag."
  ;; HTML Standard, section 13.2.6.4.4, the "in head" insertion mode
  #{:base :basefont :bgsound :link :meta :noframes :noscript :script :style
    :template :title})

(defn- tag
  "The tag of `node`, or nil for text."
  [node]
  (when (vector? node)
    (first node)))

(defn- unwrapped
  "The `nodes` with the children of each element of `t` in its place."
  [t nodes]
  (mapcat #(if (= t (tag %)) (drop 2 %) [%]) nodes))

(defn head
  "The elements in the head of the page with the `nodes`, where a browser
  puts them: those of its head element and those before its first
  content."
  [nodes]
  (->> nodes
       (unwrapped :html)
       (unwrapped :head)
       (remove #(and (string? %) (str/blank? %)))
       (take-while #(head-tags (tag %)))))

(defn- elements
  "The elements of the page with the `nodes`, at any depth."
  [nodes]
  (filter vector? (mapcat #(tree-seq vector? (partial drop 2) %) nodes)))

(defn- absolute
  "The `href` made absolute against `base`, or as it is without a base."
  [base href]
  (if base
    (url/absolute-url base href)
    href))

;; HTML Standard, sections 4.2.3 and 4.2.4
;; RFC 8288, section 3.3; HTML Standard, section 4.6.7: a rel is a list of
;; relation types in any case
(defn- link
  "The link of the `rel` to `href`, made absolute against `base`, as a map
  of its :rels, a set of relation types in lower case, and its :href. Nil
  for an href that doesn't resolve."
  [base rel href]
  (when-let [href (absolute base href)]
    {:rels (set (str/split (str/lower-case (str rel)) #"\s+"))
     :href href}))

(defn page-links
  "The links of the link elements of the page with the Hiccup `nodes` at
  `url`, made absolute against the page's base. They're those in its head,
  or in all of it by :body-links? in `opts`.

  The base is that of a base element in the head, since one in the body
  can come from anyone who writes there."
  [nodes url {:keys [body-links?] :as opts}]
  (let [head  (head nodes)
        attrs (fn [t xs]
                (keep #(when (= t (tag %)) (second %)) xs))
        base  (or (some->> (attrs :base head)
                           (keep :href)
                           first
                           (absolute url))
                  url)]
    (keep (fn [{:keys [rel href]}] (link base rel href))
          (attrs :link (if body-links? (elements nodes) head)))))

;; RFC 8288, section 3
(defn header-links
  "The links of the Link headers of the `response`, made absolute against
  the URL of the response."
  [{:keys [url headers] :as response}]
  (keep (fn [{:keys [rel href]}] (link url rel href))
        (headers/links headers)))

(defn links
  "The links of the `response` and of its page of Hiccup `nodes`, by `opts`:
  those of its Link headers first, in their order, and then those of its
  link elements, as page-links has them."
  [response nodes opts]
  (concat (header-links response)
          (page-links nodes (:url response) opts)))

(defn hrefs
  "The hrefs of the `links` with the relation type `rel`, in their order,
  each where it first appears."
  [rel links]
  (let [rel (str/lower-case rel)]
    (distinct (keep #(when (contains? (:rels %) rel) (:href %)) links))))
