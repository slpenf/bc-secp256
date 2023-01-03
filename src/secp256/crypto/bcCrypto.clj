(ns secp256.crypto.bcCrypto
  (:require [clojure.tools.logging :as log]
   	        [clojure.tools.logging.impl :as logimpl :exclude (name enabled?)])
  (:import [org.slf4j LoggerFactory Logger]
  	       [java.util.logging Level])
  (:import org.bouncycastle.jce.provider.BouncyCastleProvider)
  (:import [java.security Security KeyFactory Signature])
  (:import org.bouncycastle.asn1.sec.SECNamedCurves)
  (:import [org.bouncycastle.crypto.params ECDomainParameters 
  										   ECPrivateKeyParameters
  										   ECPublicKeyParameters])
  (:import [org.bouncycastle.jce ECPointUtil])
  (:import [org.bouncycastle.jce.spec ECPublicKeySpec])
  (:import org.bouncycastle.math.ec.ECPoint)
  (:import org.bouncycastle.jce.ECNamedCurveTable)
  (:import org.bouncycastle.util.encoders.Hex)
  (:import org.bouncycastle.crypto.signers.ECDSASigner)
  (:import java.security.KeyPairGenerator)    
  (:import org.bouncycastle.jce.spec.ECNamedCurveSpec)
  (:import org.bouncycastle.asn1.sec.SECNamedCurves)
  (:import org.bouncycastle.jce.ECNamedCurveTable)
  (:import org.bouncycastle.asn1.DERSequenceGenerator)
  (:import org.bouncycastle.asn1.ASN1Integer)
  (:import org.bouncycastle.crypto.signers.HMacDSAKCalculator)
  (:import org.bouncycastle.crypto.digests.SHA256Digest)
  (:import java.io.ByteArrayOutputStream)
  (:import java.security.SecureRandom)
  (:import java.math.BigInteger))

(def logger (ref (org.slf4j.LoggerFactory/getLogger "secp256k1.crypto.bcCrypto")))

(Security/addProvider (BouncyCastleProvider.))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by BouncyCastle that is used often"}
  curve
  (let [params (SECNamedCurves/getByName "secp256k1")]
    (ECDomainParameters. (.getCurve params)
                         (.getG params)
                         (.getN params)
                         (.getH params)
                         (.getSeed params))))

(defn getCurve [] curve)

(defonce
	^:private
	^{:doc "Singleton used with signature verification"}
	keyfactory 
	(KeyFactory/getInstance "ECDSA" "BC"))

(defn getKeyFactory [] keyfactory)

(.debug @logger (str "keyfactory and curve created"))

(defn getXYPublicPoints [keystr]
	"Takes a private key in string form of it hex representation of D and
	 calculates the X and Y values that represent the public-key. "
	(let [bigInt (BigInteger. 1 (Hex/decode keystr))
		  ;curve (SECNamedCurves/getByName "secp256k1")
		  curvePt (.normalize (.multiply (.getG curve) bigInt))
		  curvePtX (.toBigInteger (.getXCoord curvePt))
		  curvePtY (.toBigInteger (.getYCoord curvePt))]
		(hash-map :x curvePtX :y curvePtY)))

(defn get-public-key
	"Extract public key as a byte array based on a private key to be 
	 used as the address uncompressed"
	[keystr] ; keystr is a hex of the private key
	(let [bigInt (BigInteger. 1 (Hex/decode keystr))
		  ;spec (ECNamedCurveTable/getParameterSpec "secp256k1")
		  pointQ (.normalize (.multiply (.getG curve) bigInt))]
		   (.getEncoded pointQ false)))

(defn get-public-key-str [privKeyStr]
	(Hex/toHexString (get-public-key privKeyStr)))

(defn public-key-spec [pubkeystr]
	"Create a public key spec to be used in signing digital content"
	(let [spec (ECNamedCurveTable/getParameterSpec "secp256k1")
		  pubkeyhex (.decodePoint (.getCurve curve) (Hex/decode pubkeystr))]
		  (ECPublicKeySpec. pubkeyhex spec)))

(defn public-key-parms [pubkeystr]
	(ECPublicKeyParameters. (.decodePoint (.getCurve curve) (Hex/decode pubkeystr)) curve))

(defn verify-signature 
	"Verify any incoming data based on the signature and address (publickey)"
	; add exception handling when logging is added return false on exception
	[data-in signature pubkey-in]
	(let [pkspec (public-key-spec pubkey-in)
		  pubkey (.generatePublic keyfactory pkspec)
		  sig (Signature/getInstance "NONEwithECDSA")]
		(.initVerify sig pubkey)
		(.update sig (Hex/decode data-in))
		(.verify sig (Hex/decode signature))))

(defn convert-signature [rands]
	(let [s (ByteArrayOutputStream.)
		  der (DERSequenceGenerator. s)]
		  (.addObject der (ASN1Integer. (first rands)))
		  (.addObject der (ASN1Integer. (second rands)))
		  (.close der)
		  (.toByteArray s)))

(defn generate-RSPair 
	"Generate a secp256k1 signature using the private key string and data-in"
	[^String privkeystr ^String data-in ]
	(let [bigInt (BigInteger. 1 (Hex/decode privkeystr))
		  sig (ECDSASigner. (HMacDSAKCalculator. (SHA256Digest.)))
		  prvparms (ECPrivateKeyParameters. bigInt (getCurve))]
       (.init sig true prvparms)
       (.generateSignature sig (Hex/decode data-in))))

(defn generate-signature 
	  [^String privkeystr ^String data-in ] 
	  (let [rsPair (generate-RSPair privkeystr data-in)
	  	    bArry (convert-signature rsPair)]
	  	    (Hex/toHexString bArry)))

(defn generateKeyPair
	"Generate a valid keypair (private/public) for Koblitz elliptical curve secp256k1"
	[]
	(let [kgp (KeyPairGenerator/getInstance "ECDSA" "BC")
          ps (ECNamedCurveTable/getParameterSpec "secp256k1")
          _  (.initialize kgp ps (SecureRandom.))]
          (.generateKeyPair kgp)))

(defn keyPair-privkey-string 
	"Converts the private key portion of a key pair's D value and remove leading 2 zeros"
	[keypair]
	(let [kstr (Hex/toHexString (.toByteArray (.getD (.getPrivate keypair))))]
		(if (= (.substring kstr 0 2) "00") (.substring kstr 2) kstr)))
