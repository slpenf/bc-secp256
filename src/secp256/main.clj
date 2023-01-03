(ns secp256.main
	(:require [secp256.crypto.bcCrypto :refer :all])
	(:require [secp256.crypto.bcHashes :refer :all]) 
         ;[sha256 sha256-str double-sha256 ripemd-160 merkle-root]])
	(:require [yaml.core :as yaml])
	(:import java.io.File)
	(:import (java.security SecureRandom KeyPair))
	(:import org.bouncycastle.util.encoders.Hex)
	(:import org.bouncycastle.crypto.generators.ECKeyPairGenerator)
	(:import org.bouncycastle.crypto.params.ECKeyGenerationParameters)
	(:import org.bouncycastle.crypto.generators.ECKeyPairGenerator)
 (:import java.security.KeyPairGenerator)
 (:import (org.bouncycastle.jcajce.provider.asymmetric.ec BCECPublicKey))   
	(:import org.bouncycastle.jce.spec.ECNamedCurveSpec)
	(:import org.bouncycastle.asn1.sec.SECNamedCurves)
	(:import org.bouncycastle.jce.ECNamedCurveTable)
  (:gen-class))

(set! *warn-on-reflection* true)
  

(defn getConfig [name]
	(let [f (File. (str name))]
		(if (.exists f)  
			(yaml/from-file name)
			(do (.createNewFile f)
				(spit name (str "configname: " name "\nconfigType: yaml"))
                (yaml/from-file name)))))


(defn -main
  "I don't do a whole lot ... yet."
  [& args]

  (def keypair (generateKeyPair))
  (def kpX (.toBigInteger (.getXCoord (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair)))))
  (def kpY (.toBigInteger (.getYCoord (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair)))))
  (def kpPrvKeyStr (keyPair-privkey-string keypair))
  (def pts (getXYPublicPoints kpPrvKeyStr))

  (let [keypair (generateKeyPair)
			  ;kpPrvKeyStr (Hex/toHexString (.toByteArray (.getD (.getPrivate keypair))))
        kpPrvKeyStr (keyPair-privkey-string keypair)
			     data (Hex/toHexString (.generateSeed (SecureRandom.) 32))
			     sig  (generate-signature kpPrvKeyStr data)
			     pubkey-str (Hex/toHexString (.getEncoded (.getQ ^BCECPublicKey (.getPublic ^KeyPair keypair)) false))]
			  (println "verified Signature?: " (verify-signature data sig pubkey-str)))

  (println "secp256 main finished"))
