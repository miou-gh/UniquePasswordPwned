using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Flurl.Http;

namespace UniquePasswordPwned
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Write("You must specify the directory path which contains the password text files as the first argument.");
                return;
            }

            if (args.Length > 1)
            {
                Console.Write("You must specify only one argument - ensure your directory path is enclosed in quotes.");
                return;
            }

            if (!Directory.Exists(args[0]))
            {
                Console.Write("You must specify an existing directory containing the password text files.");
                return;
            }

            var files = Directory.GetFiles(args[0], "*.txt");
            var count = files.Length;
            var index = 0;

            foreach (var path in files)
            {
                ++index;

                var content = File.ReadAllText(path);

                // ignore any files that contain any non-empty extra lines.
                if (content.Split(new[] { '\n' }).Skip(1).Any(line => !string.IsNullOrEmpty(line)))
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("[SKIP] " + new FileInfo(path).Name + " " + "(" + index + " of " + count + ")");
                    Console.ResetColor();

                    continue;
                }

                var password = content.Replace("\n", "").Replace("\r", "");

                if (string.IsNullOrEmpty(password))
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("[SKIP] " + new FileInfo(path).Name + "(" + index + " of " + count + ")" + " " + "(" + index + " of " + count + ")");
                    Console.ResetColor();
                }

                Thread.Sleep(1200);
                var status = PasswordCheck.IsPwned(password).Result;

                if (status)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[VLUN] " + new FileInfo(path).Name + " " + "(" + content + ")" + " " + "(" + index + " of " + count + ")");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[SAFE] " + new FileInfo(path).Name + " " + "(" + content + ")" + " " + "(" + index + " of " + count + ")");
                    Console.ResetColor();
                }
            }

            Console.ResetColor();
            Console.WriteLine("[DONE] The password check operation has completed.");
        }
    }

    /// <summary>
    /// HaveIBeenPwned Pwned Passwords service.
    /// </summary>
    public static class PasswordCheck
    {
        /// <summary>
        /// If the password is compromised, the result will be <see langword="true"/>.
        /// </summary>
        /// <param name="password"> The password to check, ensure there are no new lines as they are not removed prior to hashing. </param>
        /// <param name="length"> The substring of the password hash to check. </param>
        /// <returns></returns>
        public static async Task<bool> IsPwned(string password, int length = 5)
        {
            if (length > 20)
                throw new ArgumentException("The length specified must be equal to or below 20 characters in length; the maximum length for a SHA-1 hash.");

            try
            {
                await Task.Delay(500); // prevent flooding requests.

                var hash = GenerateHash(password);
                var subhash = hash.Substring(0, length);
                var response = await new FlurlClient("https://api.pwnedpasswords.com").AllowHttpStatus("200")
                    .Request("/range/" + subhash).GetStringAsync();

                foreach (var line in response.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (subhash + line.Split(':')[0] == hash)
                        return true;
                }

                return false;
            }
            catch (FlurlHttpException ex)
            {
                if ((int)ex.Call.Response.StatusCode == 429)
                {
                    var delay = ex.Call.Response.GetHeaderValue("Retry-After");

                    if (!string.IsNullOrEmpty(delay))
                    {
                        if (!int.TryParse(delay, out var seconds))
                            throw new Exception("Invalid Retry-After header in HIBP Unique Password Check response.", ex);

                        await Task.Delay(new TimeSpan(0, 0, 0, seconds, 100));

                        return await IsPwned(password);
                    }
                }
                else
                {
                    throw new Exception("An unhandled API response occurred in HIBP Unique Password Check.", ex);
                }
            }

            return false;
        }

        private static string GenerateHash(string password) =>
            BitConverter.ToString(System.Security.Cryptography.SHA1.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(password))).Replace("-", "");
    }
}
