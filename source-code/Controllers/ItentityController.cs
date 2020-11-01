using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Azure;
using System.Collections.Specialized;
using Newtonsoft.Json;
using System.Reflection;
using System.Net;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace password_history.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class IdentityController : ControllerBase
    {
        private static string keyVaultName = Environment.GetEnvironmentVariable("KEY_VAULT_NAME");
        private string kvUri = "https://" + keyVaultName + ".vault.azure.net";
        private readonly ILogger<IdentityController> _logger;

        public IdentityController(ILogger<IdentityController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        public async Task<ActionResult> GetAsync()
        {
            StringCollection passwords = null;

            var client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
            KeyVaultSecret secret = null;
            string returnValue = string.Empty;

            string input = null;

            // If not data came in, then return
            if (this.Request.Body == null)
            {
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("Request content is null", HttpStatusCode.Conflict));
            }

            // Read the input claims from the request body
            using (StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8))
            {
                input = await reader.ReadToEndAsync();
            }

            // Check input content value
            if (string.IsNullOrEmpty(input))
            {
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("Request content is empty", HttpStatusCode.Conflict));
            }

            // Convert the input string into InputClaimsModel object
            InputClaimsModel inputClaims = InputClaimsModel.Parse(input);

            if (string.IsNullOrEmpty(inputClaims.userId))
            {
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("The 'userId' parameter is null or empty", HttpStatusCode.Conflict));
            }

            if (string.IsNullOrEmpty(inputClaims.password))
            {
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("The 'password' parameter is null or empty", HttpStatusCode.Conflict));
            }

            // HASH the input password
            inputClaims.password = GetPasswordHashString(inputClaims.password);

            // Trim the password
            if (inputClaims.password.Length > 55)
                inputClaims.password = inputClaims.password.Substring(0, 55);

            try
            {
                // Try to get the secret
                secret = await client.GetSecretAsync(inputClaims.userId);
            }
            catch (RequestFailedException)
            {
                _logger.LogInformation($"Secret {inputClaims.userId} not found.");
            }
            catch (Exception ex)
            {
                _logger.LogInformation(ex.Message);
            }
            if (secret != null)
            {
                try
                {
                    // If secret found, try to deserialize it
                    passwords = JsonConvert.DeserializeObject<StringCollection>(secret.Value);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Secret {inputClaims.userId} can't be deserialized.");
                }
            }

            // If both the secret not found, or can't be deserialized
            if (passwords == null)
            {
                passwords = new StringCollection();
                _logger.LogInformation("Creating new password collection for {userId}");
            }

            // Check if the password already in used
            if (passwords.Contains(inputClaims.password))
            {
                _logger.LogInformation("Secret {userId} found, returning error message ot the user.");
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("Please make sure the password you enter have never been used before.", HttpStatusCode.Conflict));
            }

            // Add the new password at the begining of the collection
            passwords.Insert(0, inputClaims.password);

            // Calculate the collection length
            int passwordsLength = 4;

            if (passwords.Count < 4)
            {
                passwordsLength = passwords.Count;
            }
            _logger.LogInformation("Secret {userId} collection length {passwordsLength}.");

            // Take the first 4 elements
            StringCollection passwordsToPersist = new StringCollection();
            for (int i = 0; i < passwordsLength; i++)
            {
                passwordsToPersist.Add(passwords[i]);
            }

            string json = JsonConvert.SerializeObject(passwordsToPersist);

            try
            {
                // Try to update the secret
                KeyVaultSecret persistedSecret = await client.SetSecretAsync(inputClaims.userId, json);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
            }

            return Ok();
        }

        public static byte[] GetPasswordHash(string inputString)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
                return algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
        }

        public static string GetPasswordHashString(string inputString)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in GetPasswordHash(inputString))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }
    }

    public class InputClaimsModel
    {
        // Demo: User's object id in Azure AD B2C
        public string userId { get; set; }
        public string password { get; set; }
        public string language { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static InputClaimsModel Parse(string JSON)
        {
            return JsonConvert.DeserializeObject(JSON, typeof(InputClaimsModel)) as InputClaimsModel;
        }
    }
    public class B2CResponseModel
    {
        public string version { get; set; }
        public int status { get; set; }
        public string userMessage { get; set; }

        // Optional claims


        public B2CResponseModel(string message, HttpStatusCode status)
        {
            this.userMessage = message;
            this.status = (int)status;
            this.version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        }
    }
}
