using System;
using System.Collections.Generic;
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


            utilizator.getInfo();
            //utilizator.credentialsExtendTransaction();

            // 1 workflow

            utilizator.authLogin();

            utilizator.credentialsList();

            utilizator.credentialsInfo();

            //utilizator.credentialsSendOTP();

            List<string> pdfList = new List<string>();
            pdfList.Add("uart.pdf");

            // if SCAL == 2
            utilizator.credentialsAuthorize(pdfList);
            utilizator.signSingleHash(pdfList);
            // else
            // utilizator.signSingleHash(pdfList);


            // if SCAL == 2
            //utilizator.credentialsAuthorize(pdfList);
            //utilizator.signMultipleHash(pdfList);
            //else
            //utilizator.signMultipleHash(pdfList);

            //utilizator.authRevoke();

            // 2 workflow

            //utilizator.oauth2Auth();


            Console.WriteLine("/----------------------/");
            utilizator.oauth2Token();


        }
    }
}
