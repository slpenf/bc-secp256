(ns secp256.crypto.bcHashes
  "Hashing utilities used for elliptic curve cryptography"
  (:import
   java.security.MessageDigest
   org.bouncycastle.crypto.digests.RIPEMD160Digest
   org.bouncycastle.crypto.digests.SHA256Digest
   org.bouncycastle.crypto.macs.HMac
   org.bouncycastle.crypto.params.KeyParameter
   org.bouncycastle.crypto.signers.ECDSASigner)
  (:import org.bouncycastle.util.encoders.Hex))

 (defprotocol ByteSerializable
   "Serialize data into a byte array"
   (to-bytes [this]))

 (extend-protocol ByteSerializable
   (Class/forName "[B") (to-bytes [ba] ba)
   String (to-bytes [s] (.getBytes s "UTF-8"))
   clojure.lang.Sequential (to-bytes [ba] (byte-array ba)))


(defn sha256
  "Get the SHA256 hash and return a byte-array"
  [& data]
  (let [d (MessageDigest/getInstance "SHA-256")]
    (doseq [datum data]
      (.update d (to-bytes datum)))
    (.digest d)))

;; Use bouncycastle because javax.crypto.Mac
;; doesn't support empty keys (one of the standard test vectors)
(defn hmac-sha256
  "Compute the HMAC given a private key and data using SHA256"
  [k data]
  (let [data (to-bytes data)
        hmac (doto (HMac. (SHA256Digest.))
               (.init (KeyParameter. (to-bytes k)))
               (.update data 0 (count data)))
        o (byte-array (.getMacSize hmac))]
    (.doFinal hmac o 0)
    o))

(defn ripemd-160
  "Get the ripemd-160 hash"
  [& data]
  (let [d (RIPEMD160Digest.)
        o (byte-array (.getDigestSize d))]
    (doseq [datum data]
      (let [datum (to-bytes datum)]
        (.update d datum 0 (count datum))))
    (let [o (byte-array (.getDigestSize d))]
      (.doFinal d o 0)
      o)))


(def double-sha256 (comp sha256 sha256))

(defn sha256-str [str-in]
  (Hex/toHexString (sha256 str-in)))

(defn- length-to-add [count-in]
    (loop [x 0 ret 0] 
        (if (>= ret count-in) 
          (- ret count-in) 
          (recur (inc x) (int (Math/pow 2 x))))))


(defn- just-two 
  "Given a list of hashes, take the first and second in the list, combine and return a double hash of it"
  [hashlist]
  (let [comb (str (first hashlist) (second hashlist))]
    (Hex/toHexString (double-sha256 comb))))

(defn- merkle-list [hashlist]
    (loop [i 0 ml []]
      (if (>= i (/ (count hashlist) 2))
         (if (> (count ml) 1) (merkle-list ml) (first ml))
         (recur (+ i 2) (conj ml (just-two (subvec hashlist i (+ i 2)))))))
  )

(defn merkle-root [hashlist]
  (let [add-len (length-to-add (count hashlist))
        holdLast (last hashlist)
        revisedList (loop [l 0 rlst hashlist]
                        (if (>= l add-len) rlst
                          (recur (inc l) (conj rlst holdLast))))]
        (merkle-list revisedList)))
