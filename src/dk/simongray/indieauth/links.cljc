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
(defn page-links
  "The link elements of the page with the Hiccup `nodes` at `url`, as maps
  of :rel and :href, made absolute against the page's base. They're those
  in its head, or in all of it by :body-links? in `opts`.

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
    (for [{:keys [rel href]} (attrs :link (if body-links? (elements nodes) head))
          :when              href
          :let               [href (absolute base href)]
          :when              href]
      {:rel rel :href href})))

;; RFC 8288, section 3
(defn header-links
  "The links of the Link headers of the `response`, as maps of :rel and
  :href, made absolute against the URL of the response."
  [{:keys [url headers] :as response}]
  (for [{:keys [rel href]} (headers/links headers)
        :let               [href (absolute url href)]
        :when              href]
    {:rel rel :href href}))

;; RFC 8288, section 3.3; HTML Standard, section 4.6.7
(defn relation?
  "Whether `rel` is one of the relation types of `link`, a list of words in
  any case."
  [rel link]
  (let [types (str/split (str/lower-case (str (:rel link))) #"\s+")]
    (boolean (some #{(str/lower-case rel)} types))))

(defn hrefs
  "The hrefs of the `links` with the relation type `rel`, in their order."
  [rel links]
  (keep #(when (relation? rel %) (:href %)) links))

(defn rel-urls
  "The URLs that the `response` and its page of Hiccup `nodes` name with the
  relation type `rel`, by `opts`: those of its Link headers first, in their
  order, and then those of its link elements, as page-links has them. A
  URL comes once, where it first appears."
  [rel response nodes opts]
  (distinct (concat (hrefs rel (header-links response))
                    (hrefs rel (page-links nodes (:url response) opts)))))
