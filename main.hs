{-# LANGUAGE OverloadedStrings #-}
import Control.Monad.Trans.Resource (runResourceT)
import Data.Monoid ((<>))
import Text.Show.Pretty (ppShow)

import qualified Data.ByteString.Char8 as BS
import qualified Network.HTTP.Client as Http
import qualified Network.HTTP.Client.TLS as HttpTls
import qualified System.Environment as Env

import Network.HTTP.Client.OpenSSL (opensslManagerSettings, withOpenSSL)
import qualified OpenSSL.Session as Ssl

import Data.Default (def)
import qualified Data.X509.CertificateStore as X509
import Network.Connection (TLSSettings (..))
import Network.HTTP.Client (ManagerSettings)
import Network.HTTP.Client.TLS (mkManagerSettings)
import Network.TLS (ClientParams (..), Shared (..), Supported (..),
                    defaultParamsClient)
import Network.TLS.Extra.Cipher
import System.IO.Unsafe (unsafePerformIO)
import qualified System.X509 as X509
import Data.Time.Clock (getCurrentTime, diffUTCTime)

import Criterion
import Criterion.Main

time action = do
    startTime <- getCurrentTime
    result <- action
    endTime <- getCurrentTime

    putStrLn $ "Time " ++ show (endTime `diffUTCTime` startTime)

    return result

main :: IO ()
main = withOpenSSL $ do
    let url = "https://930-EMI-667.mktorest.com/rest/v1/leads.json"
    let file = "main.hs"
    let authnToken = "assdf"

    -- [url, file, authnToken] <- Env.getArgs
    contents <- BS.readFile file
    req' <- Http.parseUrl url
    let req = req'
            { Http.method = "POST"
            , Http.checkStatus = \_ _ _ -> Nothing
            , Http.requestHeaders =
                [ ("Content-Type", "application/json")
                , ("Authorization", "Bearer " <> BS.pack authnToken)
                ]
            , Http.requestBody = Http.RequestBodyBS contents
            }

    tlsConnPool <- Http.newManager tlsManagerSettings
    osslConnPool <- Http.newManager (opensslManagerSettings Ssl.context)

    defaultMain
        [ bench "tls"     $ whnfIO $ Http.httpLbs req tlsConnPool
        , bench "openssl" $ whnfIO $ Http.httpLbs req osslConnPool
        ]

    return ()

globalCertificateStore :: X509.CertificateStore
globalCertificateStore =
    unsafePerformIO $ X509.getSystemCertificateStore
{-# NOINLINE globalCertificateStore #-}

tlsManagerSettings :: ManagerSettings
tlsManagerSettings = do
    mkManagerSettings tlsSettings Nothing
  where
    -- tlsSettings = def
    tlsSettings = TLSSettings (defaultParamsClient "" "")
        { clientShared = def
            { sharedCAStore = globalCertificateStore
            , sharedValidationCache = def
            }
        , clientSupported = def
            { supportedCiphers =
                [ cipher_ECDHE_ECDSA_AES128GCM_SHA256
                -- As of tls-1.3.3, cipher_ECDHE_RSA_AES128GCM_SHA256 has an intermittent failure condition:
                -- <https://github.com/vincenthz/hs-tls/issues/124>
                -- andy 4 Nov 2015
                -- , cipher_ECDHE_RSA_AES128GCM_SHA256
                , cipher_DHE_RSA_AES256_SHA256
                , cipher_DHE_RSA_AES128_SHA256
                , cipher_DHE_RSA_AES256_SHA1
                , cipher_DHE_RSA_AES128_SHA1
                , cipher_DHE_DSS_AES256_SHA1
                , cipher_DHE_DSS_AES128_SHA1
                , cipher_AES128_SHA256
                , cipher_AES256_SHA256
                , cipher_AES128_SHA1
                , cipher_AES256_SHA1
                , cipher_DHE_DSS_RC4_SHA1
                , cipher_RC4_128_SHA1
                , cipher_RC4_128_MD5
                , cipher_RSA_3DES_EDE_CBC_SHA1
                , cipher_DHE_RSA_AES128GCM_SHA256
                ]
            }
        }
