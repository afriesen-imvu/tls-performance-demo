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

main :: IO ()
main = withOpenSSL $ do
    let url = "https://localhost.imvu.com"
    let file = "main.hs"
    let authnToken = "assdf"

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

    let osslCtx = do
            ctx <- Ssl.context
            Ssl.contextSetCiphers ctx "RSA:3DES:EDE:CBC:SHA1"
            return ctx

    osslConnPool <- Http.newManager (opensslManagerSettings osslCtx)

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
    tlsSettings = TLSSettings (defaultParamsClient "" "")
        { clientShared = def
            { sharedCAStore = globalCertificateStore
            , sharedValidationCache = def
            }
        , clientSupported = def
            { supportedCiphers =
                [ cipher_RSA_3DES_EDE_CBC_SHA1 ]
            }
        }
