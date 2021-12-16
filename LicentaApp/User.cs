using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.IO;
using static System.Net.Mime.MediaTypeNames;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using RestSharp;
using RestSharp.Authenticators;
using Newtonsoft.Json.Linq;

namespace LicentaApp
{
    class User
    {
        // Credentiale
        private string username
        {
            get; set;
        }
        private string password
        {
            get; set;
        }
     
        // Credentiale aplicatie
        
        
        private int expiresIn
        {
            get;set;
        }

        #region AUTH/LOGIN
        // campuri AUTH/LOGIN --------------------

        // input =====

        private bool refreshTokenAuthBool = false;
        private bool rememberMeAuthBool = false;
        private string clientDataAuthString = "12345678";


        // output =====
        private string accessToken
        {
            get; set;
        }
        private string refresh_token
        {
            get; set;
        }

        private int accessTokenExpiresIn;

        // ---------------------------------------
        #endregion AUTH/LOGIN

        #region CREDENTIALS/LIST
        // campuri CREDENTIALS/LIST --------------------

        // input =====

        private string userID = null;
        private int maxResults = 0;
        private string clientDataCredListString = null;

        // output =====

        private List<string> credentialsIDs = new List<string>();

        // ---------------------------------------------
        #endregion CREDENTIALS/LIST



        #region CREDENTIALS/INFO
        // campuri CREDENTIALS/INFO --------------------

        // input =====

        private string credentialsCertificatesSelect = "single";
        private bool credentialsCertInfoBool = true;
        private bool credentialsAuthInfoBool = true;
        private string credentialsLang;
        private string clientDataCredInfoString = null;

        // output =====

        private List<string> credentialKeys = new List<string>();
        private string authMode;
        private bool hasPIN;
        private bool hasOTP;
        private int multisign;
        private int SCAL = 1;

        // ---------------------------------------------
        #endregion CREDENTIALS/INFO


        private bool revokeAccessTokenBool = true;
        private bool revokeRefreshTokenBool = true;
        private bool clientDataRevokeBool = false;
        private int expiresTokensIn;






        #region CREDENTIALS/AUTHORIZE

        // campuri CREDENTIALS/AUTHORIZE --------------------

        // input =====

        private string credAuthorizeDescription = null;
        private string credAuthorizeClientData = null;
        private string PIN = "12345678";
        private string OTP = "123456";
        int numSignatures = 1;

        // output =====

        private string SAD;
        private int expiresSADin = 3600;

        // --------------------------------------------------
        #endregion CREDENTIALS/AUTHORIZE


        #region SIGN/SIGNHASH
        private List<string> signatures = new List<string>();
        #endregion SIGN/SIGNHASH



        public User(string Username, string Password)
        {
            username = Username;
            password = Password;
        }


        public void getInfo()
        {
            string data = "{\"lang\":\"en-US\"}";

            var client = new RestClient("https://service.csctest.online/csc/v1/info");

            var request = new RestRequest();

            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());
        }

        public void authLogin()
        {
            // CHOOSE OPTIONS
            bool ok = false;
            string data = "{";
            if (refreshTokenAuthBool)
            {
                data += "\"" + refresh_token + "\"";
                ok = true;
            }
            if (rememberMeAuthBool)
            {
                if (ok)
                {
                    data += ",";
                }
                data += "\"rememberMe\": true";
            }
            if (clientDataAuthString != null)
            {
                if (ok)
                {
                    data += ",";
                }
                data += "\"cliendData\": \"" + clientDataAuthString + "\"";
            }
            data += "}";

            string userInfo = username + ":" + password;
            string userCredEncoded = Base64Encode(userInfo);

            var client = new RestClient("https://service.csctest.online/csc/v1/auth/login");
            var request = new RestRequest();
            request.AddHeader("Authorization", "Basic " + userCredEncoded);
            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error_description != null)
            {
                Console.WriteLine("User sau parola gresite");
                return;
            }
            //else if(inform.error_description != "")
            //{
            //    Console.WriteLine("Cerere gresita");
            //}

            accessToken = inform.access_token;
            if (rememberMeAuthBool)
            {
                refresh_token = inform.refresh_token;
            }
            rememberMeAuthBool = false;

            if (inform.expires_in != null)
            {
                accessTokenExpiresIn = inform.expires_in;
            }
        }

        public void authRevoke()
        {
            string data1 = "{";
            string data2 = "{";
            if(!revokeAccessTokenBool && !revokeRefreshTokenBool)
            {
                Console.WriteLine("Nu a fost selectat un token!");
                return;
            }

            if(revokeAccessTokenBool)
            {
                data1 += "\"token\": \"" + accessToken + "\",";
                data1 += "\"token_type_hint\": \"access_token\"";

                //if(clientDataAuthBool)
                //{
                //    data1 += "," + "\"cliendData\": \"12345678\"";
                //}

                data1 += "}";

                var client = new RestClient("https://service.csctest.online/csc/v1/auth/revoke");

                var request = new RestRequest();

                request.AddHeader("Authorization", "Bearer " + accessToken);
                request.AddJsonBody(data1);

                var response = client.Post(request);

                //treat error case;
            }

            if (revokeRefreshTokenBool)
            {
                data2 += "\"token\": \"" + refresh_token + "\",";
                data2 += "\"token_type_hint\": \"refresh_token\"";

                var client = new RestClient("https://service.csctest.online/csc/v1/auth/revoke");

                var request = new RestRequest();

                request.AddHeader("Authorization", "Bearer " + refresh_token);
                request.AddJsonBody(data2);

                var response = client.Post(request);

                //treat error case;
            }
        }
        public void credentialsList()
        {
            bool ok = false;
            maxResults = 10;
            string data = "{";

            if(userID != null)
            {
                data += "\"userID\": \"" + userID + "\"";
                ok = true;
            }
            
            if (maxResults != 0)
            {
                if (ok)
                {
                    data += ",";
                }
                data += "\"maxResults\": " + maxResults;
            }
            if (clientDataCredListString != null)
            {
                if (ok)
                {
                    data += ",";
                }
                data += "\"cliendData\": \"" + clientDataCredListString + "\"";
            }
            data += "}";

            if (accessToken == null)
            {
                Console.WriteLine("Nu esti autorizat");
                return;
            }

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/list");

            var request = new RestRequest();

            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error_description != null)
            {
                Console.WriteLine("Cerere invalida");
                return;
            }

            foreach (string el in inform.credentialIDs)
            {
                credentialsIDs.Add(el);
            }

            Console.WriteLine(response.Content.ToString());
        }
        public void credentialsInfo()
        {
            //credentialsCertificatesSelect = "chain";

            string data = "{";

            Console.Write("Alegeti credentialul: ");
            string choose = Console.ReadLine();

            bool ok = true;
            foreach (var credential in credentialsIDs)
            {
                if (choose == credential)
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
            {
                Console.WriteLine("Nu exista credentialele");
                return;
            }
            else
            {
                data += "\"credentialID\": \"" + choose + "\"";
            }

            
            if(credentialsCertificatesSelect != null)
            {
                data += ",\"certificates\": \"" + credentialsCertificatesSelect + "\"";
            }
            if(credentialsCertInfoBool)
            {
                data += ",\"certInfo\": true";
            }
            if(credentialsAuthInfoBool)
            {
                data += ",\"authInfo\": true";
            }
            if(clientDataCredInfoString != null)
            {
                data += ",\"clientData\": \" " + clientDataCredInfoString + "\"";
            }
            data += "}";


            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/info");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error_description != null)
            {
                Console.WriteLine("Cerere invalida");
                return;
            }

            if (inform.key.status == "enabled")
            {
                foreach (string el in inform.key.algo)
                {
                    credentialKeys.Add(el);
                }
            }
            
            authMode = inform.authMode;

            
            if(authMode == "explicit")
            {
                if (inform.PIN.presence == "true")
                {
                    hasPIN = true;
                }
                if (inform.OTP.presence == "true")
                {
                    hasOTP = true;
                }
            }
            
            if(inform.SCAL != null)
            {
                SCAL = inform.SCAL;
            }
            multisign = inform.multisign;
        }
        public void credentialsAuthorize(List<string> pdfName)
        {
            byte[] hashDocument;
            string hashedDocumentB64;

            string data = "{";

            if(SCAL == 1)
            {
                Console.WriteLine("Nu este nevoie de SAD");
                return;
            }

            
            //if isset PIN
            //if isset OTP
            //if isset credID

            Console.Write("Alegeti credentialul: ");
            string choose = Console.ReadLine();

            bool ok = true;
            foreach(var credential in credentialsIDs)
            {
                if(choose == credential)
                {
                    ok = false;
                    break;
                }
            }
            if(ok)
            {
                Console.WriteLine("Nu exista credentialele");
                return;
            }
            else
            {
                data += "\"credentialID\": \"" + choose + "\",";
            }

            
            if (numSignatures > multisign)
            {
                Console.WriteLine("Nu este autorizat credentialul pt atatea semnaturi");
                return;
            }
            else
            {
                data += "\"numSignatures\": " + numSignatures;
            }

            //if (numSignatures != pdfName.Count)
            //{
            //    Console.WriteLine("Numar inegal de hash-uri pt autorizare SAD");
            //    return;
            //}

            if (SCAL == 2)
            {
                
                if (numSignatures == 1)
                {
                    hashDocument = SHAClass.Instance.getSHA256Hash(pdfName[0]);
                    hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                    data += ",\"hash\": [\"" + hashedDocumentB64 + "\"]";
                }
                else
                {
                    data += ",\"hash\": [";
                    ok = false;
                    foreach (var name in pdfName)
                    {
                        if(ok)
                        {
                            data += ",";
                        }

                        hashDocument = SHAClass.Instance.getSHA256Hash(name);
                        hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                        data += "\"" + hashedDocumentB64 + "\"";
                        ok = true;
                    }
                    data += "]";
                }
                

            }

            if(authMode == "explicit")
            {
                if (hasPIN && PIN != null)
                {
                    data += ",\"PIN\": \"" + PIN + "\"";
                }

                if (hasOTP && OTP != null)
                {
                    data += ",\"OTP\": \"" + OTP + "\"";
                }
            }

            if(credAuthorizeDescription != null)
            {
                //add description
            }

            if (credAuthorizeClientData != null)
            {
                //add clientdatabool
                data += ",\"clientData\": \"" + credAuthorizeClientData + "\"";
            }

            data += "}";

            //Console.WriteLine(data);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/authorize");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error_description != null)
            {
                Console.WriteLine(inform.error_description);
                return;
            }

            SAD = inform.SAD;
            if(inform.expiresIn != null)
            {
                expiresSADin = inform.expiresIn;
            }
        }

        public void credentialsExtendTransaction()
        {
            byte[] hashDocument;
            string hashedDocumentB64;

            string data = "{";

            int numSignatures = 1;


            //if isset PIN
            //if isset OTP
            //if isset credID

            data += "\"credentialID\": \"" + credentialsIDs[1] + "\"";

            if (SCAL == 2)
            {
                if (numSignatures == 1)
                {
                    hashDocument = SHAClass.Instance.getSHA256Hash("uart.pdf");
                    hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                    data += ",\"hash\": [\"" + hashedDocumentB64 + "\"]";
                }
                else
                {
                    //foreach var el in listDocuments..
                }


            }
            // else if SCAL == 1 && want send hash

            data += ",\"SAD\": \"" + SAD + "\"";            
            //if (credAuthorizeClientDataBool)
            //{
            //    //add clientdatabool
            //    data += ",\"clientData\": \"12345678\"";
            //}

            data += "}";

            Console.WriteLine(data);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/extendTransaction");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error == "invalid_request")
            {
                Console.WriteLine(inform.error_description);
                return;
            }

            SAD = inform.SAD;
            if (inform.expiresIn != null)
            {
                expiresSADin = inform.expiresIn;
            }
        }

        public void credentialsSendOTP()
        {
            string data = "{";

            data += "\"credentialID\": \"" + credentialsIDs[1] + "\"";

            //if(clientDataAuthBool)
            //{
            //    data += ",\"clientData\": \"" + clientDataString + "\"";
            //}

            data += "}";

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/sendOTP");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            if(response.StatusCode.ToString() != "NoContent")
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                Console.WriteLine(inform.error_description);
            }

            Console.WriteLine("OTP send");
        }

        public void signSingleHash(List<string> pdfName)
        {
            string data = "{";

            // credential set
            data += "\"credentialID\": \"" + credentialsIDs[1] + "\"";
            data += ",\"SAD\": \"" + SAD + "\"";

            byte[] hashDocument = SHAClass.Instance.getSHA256Hash("uart.pdf");
            string hashedDocumentB64 = Convert.ToBase64String(hashDocument);
            data += ",\"hash\": [\"" + hashedDocumentB64 + "\"]";


            if(credentialKeys.ElementAtOrDefault(1) != null)
            {
                data += ",\"hashAlgo\": \"" + credentialKeys[1] + "\"";
            }
            else
            {
                data += ",\"hashAlgo\": \"2.16.840.1.101.3.4.2.1\"";
            }

            data += ",\"signAlgo\": \"" + credentialKeys[0] + "\"";


            //if (clientDataAuthBool)
            //{
            //    data += "\"clientData\": \"" + clientDataString + "\"";
            //}

            data += "}";

            //Console.WriteLine(data);

            var client = new RestClient("https://service.csctest.online/csc/v1/signatures/signHash");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            //Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            if (inform.error_description != null)
            {
                Console.WriteLine(inform.error_description);
                return;
            }

            foreach (string elem in inform.signatures)
            {
                signatures.Add(elem);
                Console.WriteLine(elem);
            }
        }

        public void signMultipleHash(List<string> pdfName)
        {
            string data = "{";

            // credential set
            data += "\"credentialID\": \"" + credentialsIDs[1] + "\"";
            data += ",\"SAD\": \"" + SAD + "\"";

            byte[] hashDocument;
            string hashedDocumentB64;

            data += ",\"hash\": [";
            bool ok = false;
            foreach (var name in pdfName)
            {
                if (ok)
                {
                    data += ",";
                }

                hashDocument = SHAClass.Instance.getSHA256Hash(name);
                hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                data += "\"" + hashedDocumentB64 + "\"";
                ok = true;
            }
            data += "]";


            if (credentialKeys.ElementAtOrDefault(1) != null)
            {
                data += ",\"hashAlgo\": \"" + credentialKeys[1] + "\"";
            }
            else
            {
                data += ",\"hashAlgo\": \"2.16.840.1.101.3.4.2.1\"";
            }

            data += ",\"signAlgo\": \"" + credentialKeys[0] + "\"";


            //if (clientDataAuthBool)
            //{
            //    data += "\"clientData\": \"" + clientDataString + "\"";
            //}

            data += "}";

            //Console.WriteLine(data);

            var client = new RestClient("https://service.csctest.online/csc/v1/signatures/signHash");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(data);

            var response = client.Post(request);

            //Console.WriteLine(response.Content.ToString());

            dynamic inform = JObject.Parse(response.Content.ToString());

            //if (inform.error == "invalid_request")
            //{
            //    Console.WriteLine(inform.error_description);
            //    return;
            //}

            foreach (string elem in inform.signatures)
            {
                signatures.Add(elem);
            }
        }


        public void signatureTimestamp()
        {

        }

        public void oauth2Auth()
        {     

            // https://service.csctest.online/csc/v0/oauth2/authorize?response_type=code&client_id=bBdNs9Fa7kMx0qnFsPk66sklrDw&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin.html&scope=service&state=12345678
        
        }

        public void oauth2Token()
        {
            // N5ZWR5JwAdYUSM5qhmgOFfe7GGBrIjqPA3wumm41rLwCT9vE
            bool redirectURL = true;
            string data = "{";
            string grant_type = "authorization_code";
            string code = "3qEX5qwNoQhezcPvxItTiACMuTbjLT3MCL403sVKDiweNGXs";

            data += "\"grant_type\": \"" + grant_type + "\"";

            if (grant_type == "authorization_code")
            {
                data += ",";
                data += "\"code\": \"" + code + "\"";
            }
            else if(grant_type == "refresh_token")
            {
                data += ",";
                data += "\"refresh_token\": \"" + refresh_token + "\"";
            }
            else if(grant_type == "client_credentials")
            {

            }

            string clientID = "bBdNs9Fa7kMx0qnFsPk66sklrDw";
            data += ",\"client_id\": \"" + clientID + "\"";


            string clientSecret = "QOui8WD8wX07hGd73KjO6pF3xwKj09PlKzx2e6Z8iILg2fmA";
            string clientAssertion = "salut";
            string clientAssertionType = "salut";

            data += ",\"client_secret\": \"" + clientSecret + "\"";

            //if (clientSecret != null)
            //{
            //    data += ",\"client_secret\": \"" + clientSecret + "\"";
            //}
            //else if(clientAssertion != null)
            //{
            //    data += ",\"client_assertion\": \"" + clientAssertion + "\"";
            //    data += ",\"client_assertion_type\": \"" + clientAssertionType + "\"";
            //}

            //string redirectURL_path = "http%3A%2F%2Flocalhost%3A8080%2Flogin.html";
            string redirectURL_path = "http://localhost:8080/login.html";
            if (redirectURL == true)
            {
                data += ",\"redirect_uri\": \"" + redirectURL_path + "\"";
            }

            // if clientDataBool
            // data += ",\"clientData\": \"" + clientDataString + "\"";

            data += "}";

            Console.WriteLine(data);

            var client = new RestClient("https://service.csctest.online/csc/v0/oauth2/token");

            var request = new RestRequest();
            
            request.AddHeader("Content-Type", "application/json");
            request.AddJsonBody(data);

            var response = client.Post(request);

            Console.WriteLine(response.Content.ToString());


            // curl -i -X POST -H "Content-Type: application/json" -d "{"""client_id""":"""bBdNs9Fa7kMx0qnFsPk66sklrDw""","""grant_type""":"""authorization_code""","""code""":"""TewAD21Y3Ayxo782OwCE2TURm4l9O0SJ6v2yRLvfPFOBehoM""","""client_secret""":"""QOui8WD8wX07hGd73KjO6pF3xwKj09PlKzx2e6Z8iILg2fmA""","""redirect_uri""":"""http://localhost:8080/login.html"""}" https://service.csctest.online/csc/v0/oauth2/token
        }

        public void oauth2Revoke()
        {

        }



        private string Base64Encode(string plaintext)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            string userEncoded = Convert.ToBase64String(plainTextBytes);
            return userEncoded;
        }

    }
}
