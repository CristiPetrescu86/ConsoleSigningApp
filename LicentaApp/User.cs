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
using LicentaApp.JsonClass;

namespace LicentaApp
{
    class User
    {
        // Credentiale
        private string username{ get; set; }
        private string password{ get; set; }

     
        // Credentiale aplicatie
        
        
        private int expiresIn{ get; set; }

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

        public List<CredentialsInfoReceiveClass> keysInfo = new List<CredentialsInfoReceiveClass>();

        // ---------------------------------------------
        #endregion CREDENTIALS/INFO


        #region AUTH/REVOKE

        private bool revokeAccessTokenBool = true;
        private bool revokeRefreshTokenBool = false;
        private bool clientDataRevokeBool = false;
        private int expiresTokensIn;

        #endregion AUTH/REVOKE


        #region CREDENTIALS/AUTHORIZE

        // campuri CREDENTIALS/AUTHORIZE --------------------

        // input =====

        private string credAuthorizeDescription = null;
        private string credAuthorizeClientData = null;
        private string PIN = "12345678";
        private string OTP = "123456";
        int numSignatures = 1;

        // output =====

        CredentialsAuthorizeReceiveClass currentSAD { get; set; }


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
            string language = "en-US";
            // choose variant
            var method = new GetInfoSendClass
            {
                lang = language
            };
            var jsonString = JsonSerializer.Serialize(method);


            var client = new RestClient("https://service.csctest.online/csc/v1/info");
            var request = new RestRequest();
            request.AddJsonBody(jsonString);
            var response = client.Post(request);

            GetInfoReceiveClass methodResponse = JsonSerializer.Deserialize<GetInfoReceiveClass>(response.Content.ToString());

            //foreach (var elem in methodResponse.methods)
            //{
            //    Console.WriteLine(elem);
            //}
            //Console.WriteLine($"Methods: {methodResponse.methods}");
            //Console.WriteLine($"Specificatii: {methodResponse.specs}");
        }

        public void authLogin()
        {
            // CHOOSE OPTIONS
            bool okRememberMe = false;
            string clientDataAux = null;

            //if (refreshTokenAuthBool)
            //{
            //    okRefresh = true;
            //}
            if (rememberMeAuthBool)
            {
                okRememberMe = true;
            }
            if (clientDataAuthString != null)
            {
                clientDataAux = clientDataAuthString;
            }

            var method = new AuthLoginSendClass
            {
                rememberMe = okRememberMe
            };
            if(clientDataAux != null)
            {
                method.clientData = clientDataAux;
            }

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            string userInfo = username + ":" + password;
            string userCredEncoded = Base64Encode(userInfo);

            var client = new RestClient("https://service.csctest.online/csc/v1/auth/login");
            var request = new RestRequest();
            request.AddHeader("Authorization", "Basic " + userCredEncoded);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            AuthLoginReceiveClass methodResponse = JsonSerializer.Deserialize<AuthLoginReceiveClass>(response.Content.ToString(),jsonSerializerOptions);

            //Console.WriteLine(methodResponse.access_token);
            //Console.WriteLine(methodResponse.expires_in);
            //Console.WriteLine(methodResponse.refresh_token);

            if (methodResponse.access_token == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error_description != null)
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }
            else
            {
                accessToken = methodResponse.access_token;
                if (rememberMeAuthBool)
                {
                    refresh_token = methodResponse.refresh_token;
                }
                rememberMeAuthBool = false;

                if (methodResponse.expires_in != 3600)
                {
                    accessTokenExpiresIn = methodResponse.expires_in;
                }
            }
        }

        public void authRevoke()
        {
            var method = new AuthRevokeSendClass();
            
            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            if(!revokeAccessTokenBool && !revokeRefreshTokenBool)
            {
                Console.WriteLine("Nu a fost selectat un token!");
                return;
            }

            if(revokeAccessTokenBool)
            {
                method.token = accessToken;
                method.token_type_hint = "access_token";
                var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

                //Console.WriteLine(jsonString);

                var client = new RestClient("https://service.csctest.online/csc/v1/auth/revoke");
                var request = new RestRequest();
                request.AddHeader("Authorization", "Bearer " + accessToken);
                request.AddJsonBody(jsonString);

                var response = client.Post(request);
                if(response.StatusCode.ToString() == "NoContent")
                {
                    Console.WriteLine("Token sters cu succes");
                }
                else
                {
                    //treat error case;
                    Console.WriteLine("Token Delete Error");
                }
                
            }

            if (revokeRefreshTokenBool)
            {
                if(refresh_token == null)
                {
                    Console.WriteLine("Nu exista acest token");
                    return;
                }

                method.token = refresh_token;
                method.token_type_hint = "refresh_token";
                var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

                var client = new RestClient("https://service.csctest.online/csc/v1/auth/revoke");
                var request = new RestRequest();
                request.AddHeader("Authorization", "Bearer " + refresh_token);
                request.AddJsonBody(jsonString);

                var response = client.Post(request);
                if (response.StatusCode.ToString() == "NoContent")
                {
                    Console.WriteLine("Token sters cu succes");
                }
                else
                {
                    //treat error case;
                    Console.WriteLine("Token Delete Error");
                }               
            }
        }
        public void credentialsList()
        {
            if (accessToken == null)
            {
                Console.WriteLine("Nu esti autorizat");
                return;
            }

            var method = new CredentialsListSendClass();
            maxResults = 10;
               
            if (maxResults != 0)
            {
                method.maxResults = maxResults;
            }
            if (clientDataCredListString != null)
            {
                method.clientData = clientDataCredListString;
            }
          
            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/list");
            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            CredentialsListReceiveClass methodResponse = JsonSerializer.Deserialize<CredentialsListReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if (methodResponse.credentialIDs.Count < 1)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error_description != null)
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }
            else
            {
                foreach (string elem in methodResponse.credentialIDs)
                {
                    credentialsIDs.Add(elem);
                    Console.WriteLine(elem);
                }
            }
        }
        public void credentialsInfo(string credentialName)
        {
            credentialsCertificatesSelect = "single";

            bool ok = true;
            foreach (var credential in credentialsIDs)
            {
                if (credentialName == credential)
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

            var method = new CredentialsInfoSendClass
            {
                credentialID = credentialName
            };

            if (credentialsCertificatesSelect != null)
            {
                method.certificates = credentialsCertificatesSelect;
            }
            if(credentialsCertInfoBool)
            {
                method.certInfo = true;
            }
            if(credentialsAuthInfoBool)
            {
                method.authInfo = true;
            }
            if(clientDataCredInfoString != null)
            {
                method.clientData = clientDataCredInfoString;
            }

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/info");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            //Console.WriteLine(response.Content.ToString());

            CredentialsInfoReceiveClass methodResponse = JsonSerializer.Deserialize<CredentialsInfoReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if(methodResponse.key.status == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error_description != null)
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }
            else
            {
                methodResponse.credentialName = credentialName;
                keysInfo.Add(methodResponse);
            }
        }
        public void credentialsAuthorize(List<string> pdfName, string credentialName)
        {
            byte[] hashDocument;
            string hashedDocumentB64;


            int index = -1;
            for (int i = 0; i < keysInfo.Count; i++)
            {
                if(keysInfo[i].credentialName == credentialName)
                {
                    index = i;
                    break;
                }
            }

            var method = new CredentialsAuthorizeSendClass();
            
            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            if(keysInfo[index].SCAL == "1")
            {
                Console.WriteLine("Nu este nevoie de SAD");
                return;
            }

            
            //if isset PIN
            //if isset OTP
            //if isset credID

            method.credentialID = keysInfo[index].credentialName;

            
            if (numSignatures > keysInfo[index].multisign)
            {
                Console.WriteLine("Nu este autorizat credentialul pt atatea semnaturi");
                return;
            }
            else
            {
                method.numSignatures = numSignatures;
            }

            //if (numSignatures != pdfName.Count)
            //{
            //    Console.WriteLine("Numar inegal de hash-uri pt autorizare SAD");
            //    return;
            //}

              
            foreach (var name in pdfName)
            {
                hashDocument = SHAClass.Instance.getSHA256Hash(name);
                hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                method.hash.Add(hashedDocumentB64);
            }


            if (keysInfo[index].authMode == "explicit")
            {
                if (keysInfo[index].PIN.presence == "true")
                {
                    method.PIN = PIN;
                }

                if (keysInfo[index].OTP.presence == "true")
                {
                    // sendOTP method folosit aici eventual, sau mai devreme
                    method.OTP = OTP;
                }
            }

            if(credAuthorizeDescription != null)
            {
                //add description
            }

            if (credAuthorizeClientData != null)
            {
                //add clientdatabool
                method.clientData = credAuthorizeClientData;
            }

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/authorize");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            //Console.WriteLine(response.Content.ToString());

            CredentialsAuthorizeReceiveClass methodResponse = JsonSerializer.Deserialize<CredentialsAuthorizeReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if(methodResponse.SAD == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error_description != null)
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }

            currentSAD = methodResponse;
        }

        public void credentialsExtendTransaction(List<string> pdfName, string credentialName)
        {
            byte[] hashDocument;
            string hashedDocumentB64;

            int index = -1;
            for (int i = 0; i < keysInfo.Count; i++)
            {
                if (keysInfo[i].credentialName == credentialName)
                {
                    index = i;
                    break;
                }
            }

            var method = new ExtendTransactionSendClass();

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            method.credentialID = keysInfo[index].credentialName;


            if (numSignatures == 1)
            {
                hashDocument = SHAClass.Instance.getSHA256Hash("uart.pdf");
                hashedDocumentB64 = Convert.ToBase64String(hashDocument);

                method.hash.Add(hashedDocumentB64);
            }
            else
            {
                //foreach var el in listDocuments..
            }

            method.SAD = currentSAD.SAD;

            //if (credAuthorizeClientDataBool)
            //{
            //    //add clientdatabool
            //    method.clientData = clientDataAuthString;
            //}

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/extendTransaction");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);
            var response = client.Post(request);

            ExtendTransactionReceiveClass methodResponse = JsonSerializer.Deserialize<ExtendTransactionReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if(methodResponse.SAD == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error == "invalid_request")
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }

            currentSAD.SAD = methodResponse.SAD;
            if(methodResponse.expiresIn != 3600 && methodResponse.expiresIn != null)
            {
                currentSAD.expiresIn = methodResponse.expiresIn;
            }
        }

        public void credentialsSendOTP(string credentialName)
        {
            int index = -1;
            for (int i = 0; i < keysInfo.Count; i++)
            {
                if (keysInfo[i].credentialName == credentialName)
                {
                    index = i;
                    break;
                }
            }

            if(index == -1)
            {
                return;
            }

            var method = new SendOTPClass();

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            method.credentialID = keysInfo[index].credentialName;

            //if(clientDataAuthBool)
            //{
            //    method.clientData = clientDataAuthString;
            //}

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/credentials/sendOTP");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            if(response.StatusCode.ToString() != "NoContent")
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                Console.WriteLine(inform.error_description);
            }

            Console.WriteLine("OTP send");
        }

        public void signSingleHash(List<string> pdfName, string credentialName)
        {
            int index = -1;
            for (int i = 0; i < keysInfo.Count; i++)
            {
                if (keysInfo[i].credentialName == credentialName)
                {
                    index = i;
                    break;
                }
            }

            if(index == -1)
            {
                Console.WriteLine("Error");
                return;
            }

            var method = new SignHashSendClass();

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            method.credentialID = keysInfo[index].credentialName;
            method.SAD = currentSAD.SAD;


            byte[] hashDocument = SHAClass.Instance.getSHA256Hash("test.pdf");
            string hashedDocumentB64 = Convert.ToBase64String(hashDocument);

            method.hash.Add(hashedDocumentB64);


            if(keysInfo[index].key.algo.ElementAtOrDefault(1) != null)
            {
                method.hashAlgo = keysInfo[index].key.algo[1];
            }
            else
            {
                method.hashAlgo = "2.16.840.1.101.3.4.2.1";   
            }

            method.signAlgo = keysInfo[index].key.algo[0];


            //if (clientDataAuthBool)
            //{
            //    data += "\"clientData\": \"" + clientDataString + "\"";
            //}

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);


            var client = new RestClient("https://service.csctest.online/csc/v1/signatures/signHash");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);

            var response = client.Post(request);

            SignHashReceiveClass methodResponse = JsonSerializer.Deserialize<SignHashReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if (methodResponse.signatures[0] == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error_description != null)
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }

            foreach (string elem in methodResponse.signatures)
            {
                signatures.Add(elem);
                Console.WriteLine(elem);
            }
        }

        public void signMultipleHash(List<string> pdfName)
        {
            //string data = "{";

            //// credential set
            //data += "\"credentialID\": \"" + credentialsIDs[1] + "\"";
            //data += ",\"SAD\": \"" + SAD + "\"";

            //byte[] hashDocument;
            //string hashedDocumentB64;

            //data += ",\"hash\": [";
            //bool ok = false;
            //foreach (var name in pdfName)
            //{
            //    if (ok)
            //    {
            //        data += ",";
            //    }

            //    hashDocument = SHAClass.Instance.getSHA256Hash(name);
            //    hashedDocumentB64 = Convert.ToBase64String(hashDocument);

            //    data += "\"" + hashedDocumentB64 + "\"";
            //    ok = true;
            //}
            //data += "]";


            //if (credentialKeys.ElementAtOrDefault(1) != null)
            //{
            //    data += ",\"hashAlgo\": \"" + credentialKeys[1] + "\"";
            //}
            //else
            //{
            //    data += ",\"hashAlgo\": \"2.16.840.1.101.3.4.2.1\"";
            //}

            //data += ",\"signAlgo\": \"" + credentialKeys[0] + "\"";


            ////if (clientDataAuthBool)
            ////{
            ////    data += "\"clientData\": \"" + clientDataString + "\"";
            ////}

            //data += "}";

            ////Console.WriteLine(data);

            //var client = new RestClient("https://service.csctest.online/csc/v1/signatures/signHash");

            //var request = new RestRequest();
            //request.AddHeader("Authorization", "Bearer " + accessToken);
            //request.AddJsonBody(data);

            //var response = client.Post(request);

            ////Console.WriteLine(response.Content.ToString());

            //dynamic inform = JObject.Parse(response.Content.ToString());

            ////if (inform.error == "invalid_request")
            ////{
            ////    Console.WriteLine(inform.error_description);
            ////    return;
            ////}

            //foreach (string elem in inform.signatures)
            //{
            //    signatures.Add(elem);
            //}
        }


        public void signatureTimestamp(List<string> pdfName, string credentialName)
        {
            byte[] hashDocument;
            string hashedDocumentB64;

            int index = -1;
            for (int i = 0; i < keysInfo.Count; i++)
            {
                if (keysInfo[i].credentialName == credentialName)
                {
                    index = i;
                    break;
                }
            }

            var method = new SignatureTimestampSendClass();

            var jsonSerializerOptions = new JsonSerializerOptions()
            {
                IgnoreNullValues = true
            };

            hashDocument = SHAClass.Instance.getSHA256Hash(pdfName[0]);
            hashedDocumentB64 = Convert.ToBase64String(hashDocument);

            method.hash = hashedDocumentB64;

            method.hashAlgo = keysInfo[index].key.algo[1];


            //if (credAuthorizeClientDataBool)
            //{
            //    //add clientdatabool
            //    method.clientData = clientDataAuthString;
            //}

            var jsonString = JsonSerializer.Serialize(method, jsonSerializerOptions);

            var client = new RestClient("https://service.csctest.online/csc/v1/signatures/timestamp");

            var request = new RestRequest();
            request.AddHeader("Authorization", "Bearer " + accessToken);
            request.AddJsonBody(jsonString);
            var response = client.Post(request);

            SignatureTimestampReceiveClass methodResponse = JsonSerializer.Deserialize<SignatureTimestampReceiveClass>(response.Content.ToString(), jsonSerializerOptions);

            if (methodResponse.timestamp == null)
            {
                dynamic inform = JObject.Parse(response.Content.ToString());
                if (inform.error == "invalid_request")
                {
                    Console.WriteLine(inform.error_description);
                    return;
                }
            }

            // save timestamp
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
