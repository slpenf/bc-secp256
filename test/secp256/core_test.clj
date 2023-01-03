(ns secp256.core-test
  (:import org.bouncycastle.util.encoders.Hex)
  (:import (java.security SecureRandom KeyPair))
  (:import (org.bouncycastle.jcajce.provider.asymmetric.ec BCECPrivateKey BCECPublicKey))
  (:require [clojure.test :refer :all]
            [secp256.crypto.bcCrypto :refer :all]
            [secp256.crypto.bcHashes :refer :all]
            [secp256.main :refer :all]))

(set! *warn-on-reflection* true)

(def privkeystr "b0c8e92caffbfcd7d998922305f8765f362f9dc8c488e631e3e7f4bf25ba7ace")

(def privkeybigint (str "79962040075280329531881212583849206785168180588451409801324957714466962307790"))
(def publicKeyXY {
	:x 69684391854151863717849787327823860431449813398071603006803936482827660682766, 
	:y 110016292775236351535756178227429887632154999162919658638248570202037145766546})

(def address (str "049a0ff7d4b92bd9fee4c35fc1528e23fc6b361625032b81485e666874e263e60ef33b03da6099e01b4fe9cdadd311a9ad840a889922e9b1c11163143577e70a92"))

(def xactHash (str "304402204c35fc089fd4a41c54e925900415d3489c912723ac134db2db88a6c239198106022023ea6b009259076f0498ad5384077be54cade960ef4f53f80fa1370598d1bac3"))

(def data "cc2c33b1c0c781afa2c498862a425af9bd14182a7cd3e5e6a7ddd72ffc76a551")

(def xactHashes (loop [x 0 hl []] 
	(if (= x 100) hl 
		(recur (inc x) (conj hl (sha256-str (str "SamIam" x)))))))


(deftest validate-private-key
  (testing "verify private key represents its BigInteger value"
  	(let [v1 (BigInteger. 1 (Hex/decode ^String privkeystr))
  		  v2 (BigInteger. ^String privkeybigint)]
    (is (= v1 v2)))))

(deftest validate-public-XY
	(testing "validate public XY values based on privkeystr"
	  (let [pts (getXYPublicPoints privkeystr)]
	  	(is (and (= (:x pts) (:x publicKeyXY))
	  		 (= (:y pts) (:y publicKeyXY)))))))

(deftest validate-verify-signature 
	(testing "verifying signature for address xactHash data"
	(is (= true (verify-signature data xactHash address)))))

(deftest validate-decoding-encoding-size
	(testing "validate that count of getBytes on aString is same (Hex/encode (hex/decode) aString)"
		(let [v1 (.getBytes ^String data)
			     v2 (Hex/encode (Hex/decode ^String data))]
			  (is (= (count v1) (count v2))))))

(deftest validate-decoding-encoding
	(testing "validate that getBytes on aString is same (Hex/encode (hex/decode) aString)"
		(let [v1 (.getBytes ^String data)
			  v2 (Hex/encode (Hex/decode ^String data))]
			  (loop [i 0]
			  	(when (< i (count v1))
			  		(is (= (get v1 i) (get v2 i)))
			  		(recur (inc i)))))))

(deftest validate-merkle-root
	(testing "validate the merkle-root calculation"
			(is (= (merkle-root xactHashes) 
				   "3116c71b3df2224e55dcefcb3a730478dade5373e592562164c4acaa58744e53"))))

(deftest validate-signature-generation
	(testing "generate a keypair, random data, sign and verify"
		(let [keypair (generateKeyPair)
			  kpPrvKeyStr (Hex/toHexString (.toByteArray (.getD ^BCECPrivateKey (.getPrivate ^KeyPair keypair))))
			  data (Hex/toHexString (.generateSeed (SecureRandom.) 32))
			  sig  (generate-signature kpPrvKeyStr data)
			  pubkey-str (Hex/toHexString (.getEncoded (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair)) false))]
			(is (= true (verify-signature data sig pubkey-str))))))

(deftest validate-key-generation
	(testing "Generate a keypair for secp256k1 and validate it with getXYPublicPoints"
		(let [keypair (generateKeyPair)
  			 kpX (.toBigInteger (.getXCoord (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair))))
  			 kpY (.toBigInteger (.getYCoord (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair))))
  			 kpPrvKeyStr (Hex/toHexString (.toByteArray (.getD ^BCECPrivateKey (.getPrivate ^KeyPair keypair))))
  		     pts (getXYPublicPoints kpPrvKeyStr)]
  		     (is (and (= kpX (:x pts)) (= kpY (:y pts)))))))