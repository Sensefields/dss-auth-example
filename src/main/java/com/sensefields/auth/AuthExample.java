package com.sensefields.auth;

import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.*;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import searchfast.cloud.auth.cognito.AWSCognitoSession;
import searchfast.cloud.auth.cognito.AWSCryptoSettings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

public class AuthExample {

    private static final String clientId = "clientId";
    private static final String poolId = "poolId";

    /**
     * Perform authentication with AWS Cognito.
     *
     * @param user    Sensefields provided API Key
     * @param secret Sensefields provided API Secret
     * @return AuthenticationResultType object that contains the ID, Access and Refresh Token.
     */
    private static AuthenticationResultType getTokens(String user, String secret) {

        //Build an anonymous Cognito client and define the region
        AWSCognitoIdentityProviderClient cognitoClient = new AWSCognitoIdentityProviderClient(new AnonymousAWSCredentials());
        cognitoClient.setRegion(Region.getRegion(Regions.EU_WEST_1));

        //Build helper objects to handle the crypto
        AWSCryptoSettings cryptoParams = new AWSCryptoSettings();
        AWSCognitoSession clientSession = new AWSCognitoSession(cryptoParams, user, secret, poolId);

        /*
        First step of the auth, pass username and SRP_A.
        This authentication is based on SRP in order to avoid the transmission of the password over the wire.
        It works by passing a SRP_A fields as a challenge to the auth server and answering to the presented challenge.
        */
        InitiateAuthRequest authRequest = new InitiateAuthRequest()
                .withAuthFlow(AuthFlowType.USER_SRP_AUTH)
                .withClientId(clientId)
                .withAuthParameters(clientSession.step1());
        InitiateAuthResult authResult = cognitoClient.initiateAuth(authRequest);

        /*
        Get the challenge in the response and generate the parameters in order to answer it correctly.
         */
        Map<String, String> params = authResult.getChallengeParameters();
        Map<String, String> srpAuthResponses = clientSession.step2(params);

        /*
        Answer the challenge with the computed parameters
         */
        RespondToAuthChallengeRequest respondToAuthChallengeRequest = new RespondToAuthChallengeRequest()
                .withChallengeName(authResult.getChallengeName())
                .withClientId(clientId)
                .withChallengeResponses(srpAuthResponses);
        RespondToAuthChallengeResult respondToAuthChallengeResult = cognitoClient.respondToAuthChallenge(respondToAuthChallengeRequest);

        /*
        If the authentication is successful, the RespondToAuthChallengeResult will contain ID,Acess and Refresh tokens.
         */
        return respondToAuthChallengeResult.getAuthenticationResult();
    }

    private static AuthenticationResultType refreshTokens(String tokenRefresh) {

        Map<String, String> authParams = new HashMap<>();
        authParams.put("REFRESH_TOKEN", tokenRefresh);

        InitiateAuthRequest authRequest = new InitiateAuthRequest()
                .withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
                .withClientId(clientId)
                .withAuthParameters(authParams);

        //Build an anonymous Cognito client and define the region
        AWSCognitoIdentityProviderClient cognitoClient = new AWSCognitoIdentityProviderClient(new AnonymousAWSCredentials());
        cognitoClient.setRegion(Region.getRegion(Regions.EU_WEST_1));

        InitiateAuthResult authResult = cognitoClient.initiateAuth(authRequest);

        return authResult.getAuthenticationResult();
    }

    /**
     * Perform an API Call with the given HTTP Headers.
     * - If the headers does not include API Key this should result in a 401 Unauthorized
     * - If the headers contain API Key but no Token -> 401 Unauthorized
     * - If API Key and Token -> 200 OK
     *
     * @param headers
     */
    private static void simpleApiCall(Map<String, String> headers) {
        String url = "https://xxxxxxx.execute-api.eu-west-1.amazonaws.com/secure/vehicles";

        HttpClient client = new DefaultHttpClient();
        HttpGet request = new HttpGet(url);
        try {

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }

            HttpResponse response = client.execute(request);
            System.out.println(response.getStatusLine());
            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

            for (String line = br.readLine(); line != null; line = br.readLine()) {
                System.out.println(line);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Performs an API Call only specifying the API Key
     *
     * @param apiKey
     */
    private static void performApiCallWithApiKey(String apiKey) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-KEY", apiKey);
        simpleApiCall(headers);
    }

    /**
     * Performs an API Call specifying API Key and Token ID
     *
     * @param apiKey
     * @param token
     */
    private static void performApiCallWithApiKeyAndToken(String apiKey, String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-KEY", apiKey);
        headers.put("Authorization", token);
        simpleApiCall(headers);
    }


    public static void main(String[] args) {
        String apiKey = "yyy";
        String username = "";
        String secret = "xxx";

        AuthenticationResultType authResult = getTokens(username, secret);

        /*
        System.out.println(authResult.getIdToken());
        System.out.println(authResult.getAccessToken());
        System.out.println(authResult.getRefreshToken());
        */

        //Perform a request without any header
        simpleApiCall(new HashMap<>());
        //Perform an API Call only with API Key, this should result in a 401 Unauthorized
        performApiCallWithApiKey(apiKey);
        //Perform an API Call with API Key and ID Token, this should result in a 200 OK
        performApiCallWithApiKeyAndToken(apiKey, authResult.getIdToken());

        //When token is expired, a call to refresh tokens must be performed
        System.out.println("******* REFRESH TOKENS *******");

        /*
        authResult = refreshTokens(authResult.getRefreshToken());
        System.out.println(authResult.getIdToken());
        System.out.println(authResult.getAccessToken());
        System.out.println(authResult.getRefreshToken());
        */

    }
}
