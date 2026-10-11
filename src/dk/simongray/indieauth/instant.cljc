(ns ^:no-doc dk.simongray.indieauth.instant
  "Instants on both platforms: a java.util.Date on the JVM, and a Date in
  JavaScript.")

(defn of-ms
  "The instant `ms` milliseconds after 1970."
  [ms]
  #?(:clj  (java.util.Date. (long ms))
     :cljs (js/Date. ms)))

(defn now
  "The instant now, by the clock of the platform."
  []
  #?(:clj  (java.util.Date.)
     :cljs (js/Date.)))

(defn later
  "The instant `seconds` after the instant `at`."
  [at seconds]
  (of-ms (+ (inst-ms at) (* 1000 seconds))))

(defn past?
  "Whether the instant `x` is at or before the instant `at`."
  [x at]
  (<= (inst-ms x) (inst-ms at)))

(defn expired?
  "Whether the map `m` has :expires, an instant at or before the instant
  `at`."
  [m at]
  (boolean (some-> (:expires m) (past? at))))

(defn epoch-seconds
  "The whole seconds since 1970 of the instant `at`."
  [at]
  (quot (inst-ms at) 1000))
