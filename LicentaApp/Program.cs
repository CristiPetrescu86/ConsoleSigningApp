using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace LicentaApp
{
    class Program
    {   
        static void Main(string[] args)
        {
            
            string user = "adobedemo";
            string pass = "password";

            User utilizator = new User(user, pass);

            // Basic authentication and authorization Workflow
            utilizator.getInfo();
            utilizator.authLogin();
            utilizator.credentialsList();
            utilizator.credentialsInfo("adobedemo_0002_explicit");

            List<string> pdfList = new List<string>();
            pdfList.Add("test.pdf");


            // if SCAL == 2
            utilizator.credentialsAuthorize(pdfList, "adobedemo_0002_explicit");
            utilizator.signSingleHash(pdfList, "adobedemo_0002_explicit");
            
            // else
            // utilizator.signSingleHash(pdfList);

            utilizator.authRevoke();


            //utilizator.credentialsExtendTransaction();
            //utilizator.credentialsSendOTP();

    
            // 2 workflow

            //utilizator.oauth2Auth();
            //Console.WriteLine("/----------------------/");
            //utilizator.oauth2Token();


        }


    }
}
