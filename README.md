# Band password history


## Setup your environment

1. Install [az](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-macos) command. 
1. Run the login command `az login`. If the CLI can open your default browser, it will do so and load an Azure sign-in page. Sign in with your account credentials in the browser. To learn more about different authentication methods, see [Sign in with Azure CLI](https://docs.microsoft.com/cli/azure/authenticate-azure-cli).
1. Check your subscription `az account show`. If required, [change the active subscription](https://docs.microsoft.com/cli/azure/manage-azure-subscriptions-azure-cli#change-the-active-subscription).  
1. Create a service principal and configure its access to Azure resources 

    ```azurecli
    az ad sp create-for-rbac -n <your-application-name> --skip-assignment command 
    ```

1. Use the returned credentials above to set keys. In your application settings add the following keys: 
    1. AZURE_CLIENT_ID - `appId`
    1. AZURE_CLIENT_SECRET - `password`
    1. AZURE_TENANT_ID - `tenant`
    1. KEY_VAULT_NAME - You key vault name.
    
    ```json
    {
      "appId": "00000000-0000-0000-0000-000000000000",
      "displayName": "key-vault-sp",
      "name": "http://key-vault-sp",
      "password": "lC9fm32te~ZmFzf-kv~LFZKgnlcH6.KWQD",
      "tenant": "11111111-1111-1111-1111-111111111111"
    }
    ```


1. Update the service principle permissions. 

    ```azurecl
    az keyvault set-policy --name <your-key-vault-name> --spn <your-app-id> --secret-permissions delete get list set
    ```

1. 