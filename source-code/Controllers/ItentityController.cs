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

            try
            {
                // Try to get the secret
                List<Passwords> passwords = new List<Passwords>();

                await foreach (SecretProperties secretVersion in client.GetPropertiesOfSecretVersionsAsync(inputClaims.userId))
                {
                    passwords.Add(new Passwords() { Version = secretVersion.Version, CreatedOn = secretVersion.CreatedOn });
                }

                // Sort the history by date decsending
                passwords = passwords.OrderByDescending(x => x.CreatedOn).ToList();

                int i = 0;
                foreach (var item in passwords)
                {
                    i++;

                    if (i <= 4)
                    {
                        secret = await client.GetSecretAsync(inputClaims.userId, item.Version);
                        // Check if the password already in used
                        if (secret.Value == inputClaims.password)
                        {
                            _logger.LogInformation("Secret {userId} found, returning error message ot the user.");
                            return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("Please make sure the password you enter have never been used before.", HttpStatusCode.Conflict));
                        }
                    }
                    else
                    {
                        break;
                    }
                }

            }
            catch (RequestFailedException)
            {
                _logger.LogInformation($"Secret {inputClaims.userId} not found.");
            }
            catch (Exception ex)
            {
                _logger.LogInformation(ex.Message);
            }


            try
            {
                // Try to update the secret
                KeyVaultSecret persistedSecret = await client.SetSecretAsync(inputClaims.userId, inputClaims.password);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                return StatusCode((int)HttpStatusCode.Conflict, new B2CResponseModel("Error (649): " + ex.Message, HttpStatusCode.Conflict));

            }

            return Ok();
        }

    }

    public class Passwords
    {
        public string Version { get; set; }
        public string password { get; set; }
        public DateTimeOffset? CreatedOn { get; set; }
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
