using System.Security.Cryptography;

namespace EncryptionUtil
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var msg = "#############  RSA Encryption Utils  #############";
            //args = new string[]
            //{


            // "-outprivate1",
            // "out.pem",
            //"-outpublic0",
            // "outpub.pem"
            // };


            Console.Clear();
            var leftPos = (Console.WindowWidth/2)- (msg.Length / 2);
            Console.SetCursorPosition(leftPos, 2);
            Console.WriteLine(msg);
            Console.WriteLine("");

            var cmdLine = string.Join(" ", args);

            Console.WriteLine($@"Called with command line of {cmdLine}");
            Console.WriteLine("");

            var useageMessage = "-outprivate <private Key name> -outpublic <public key name>";
            if(args.Length != 4)
            {
                Console.WriteLine("Incorrect number of params");
                Console.WriteLine($"Usage : {useageMessage}");
                return; 
            }

            // Convert to dictionary
            //
            Dictionary<string,string> parameters = Enumerable
                .Range(0, args.Length / 2)
                .ToDictionary(
                    i => args[i * 2].ToLower(),
                    i => args[i * 2 + 1]
                );
            // Verify the dictionary has the proper params
            // 
            var validationMessages = new List<string>();
            if (!parameters.ContainsKey("-outprivate") )
            {
                validationMessages.Add("Missing -outprivate parameter");
            }
            if (!parameters.ContainsKey("-outpublic"))
            {
                validationMessages.Add("Missing -outpublic parameter");
            }

            if (validationMessages.Count > 0)
            {

                Console.WriteLine($"Error:");
                foreach (var message in validationMessages)
                {
                    Console.WriteLine($"\t{message}");
                }
                Console.WriteLine($"");
                Console.WriteLine($"Usage : {useageMessage}");

                return;
            }

            RSA rsa = RSA.Create();
            RSAUtility verifier = new RSAUtility();
            
            var currentDirectory = Directory.GetCurrentDirectory();

            var privateKey = verifier.CreatePrivateKey(rsa);
            File.WriteAllText($@"{currentDirectory}\{parameters["-outprivate"]}", privateKey);
            Console.WriteLine($@"Writing {currentDirectory}\{parameters["-outprivate"]}");

            var publicKey = verifier.ExportPublicKey(rsa);
            File.WriteAllText($@"{currentDirectory}\{parameters["-outpublic"]}", publicKey);
            Console.WriteLine($@"Writing {currentDirectory}\{parameters["-outpublic"]}");
            Console.WriteLine("");
            Console.WriteLine($@"Process complete.");

        }
    }
}
