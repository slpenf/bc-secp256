(defproject secp256 "0.5.0-SNAPSHOT"
  :description "Provides secp256k1 support for miners and consensus processes"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [io.forward/yaml "1.0.11"]
                 [org.bouncycastle/bcprov-jdk15on "1.70"]
                 [org.bouncycastle/bcpkix-jdk15on "1.70"]
                 [io.grpc/grpc-protobuf "1.51.1"]
                 [io.grpc/grpc-netty "1.51.1" :exclusions 
                      [io.netty/netty-codec-http2 io.grpc/grpc-core]]
                 [io.grpc/grpc-stub "1.51.1"]
                 [cheshire "5.11.0"]
                 [org.slf4j/slf4j-api "2.0.6"]
                 [ch.qos.logback/logback-classic "1.4.5"]
                 [org.clojure/tools.logging "1.2.4"]
                 [org.clojure/tools.cli "1.0.214"]
                 [org.clojure/core.async "1.6.673"]]
  :main ^:skip-aot secp256.main
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
