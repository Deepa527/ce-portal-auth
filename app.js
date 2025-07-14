const {
    CognitoIdentityProviderClient,
    InitiateAuthCommand,
    GetUserCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const client = new CognitoIdentityProviderClient();

exports.handler = async (event) => {
    const corsHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
    };

    // Handle preflight (OPTIONS) requests
    if (event.httpMethod === "OPTIONS") {
        return {
            statusCode: 200,
            headers: corsHeaders,
            body: JSON.stringify({ message: "CORS preflight handled" }),
        };
    }

    try {
        const body = JSON.parse(event.body || "{}");
        const { username, password } = body;

        if (!username || !password) {
            return {
                statusCode: 400,
                headers: corsHeaders,
                body: JSON.stringify({ error: "Username and password are required" }),
            };
        }

        // Step 1: Authenticate the user
        const authCommand = new InitiateAuthCommand({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: process.env.CLIENT_ID,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password,
            },
        });

        const authResponse = await client.send(authCommand);

        const { AccessToken, IdToken } = authResponse.AuthenticationResult;

        // Step 2: Get user attributes
        const getUserCommand = new GetUserCommand({
            AccessToken: AccessToken,
        });

        const userResponse = await client.send(getUserCommand);

        // Convert attributes array to an object for easy access
        const userAttributes = {};
        for (const attr of userResponse.UserAttributes) {
            userAttributes[attr.Name] = attr.Value;
        }

        // You can customize which attributes to send
        const userProfile = {
            username: userResponse.Username,
            firstName: userAttributes["given_name"] || "",
            lastName: userAttributes["family_name"] || "",
            email: userAttributes["email"] || "",
            title: userAttributes["custom:title"] || "",
            role: userAttributes["custom:role"] || "" // if title is stored as a custom attribute
        };

        return {
            statusCode: 200,
            headers: corsHeaders,
            body: JSON.stringify({
                message: "Login successful",
                idToken: IdToken,
                accessToken: AccessToken,
                userProfile: userProfile,
            }),
        };
    } catch (err) {
        const errorMessage =
            err.name === "NotAuthorizedException" || err.name === "UserNotFoundException"
                ? "Invalid username or password"
                : err.message;

        return {
            statusCode: 401,
            headers: corsHeaders,
            body: JSON.stringify({ error: errorMessage }),
        };
    }
};