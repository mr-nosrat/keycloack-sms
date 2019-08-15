package com.alliander.keycloak.authenticator;

import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Created by IntelliJ IDEA.
 * User: amin
 * Date: Jul 6, 2010
 * Time: 11:51:41 AM
 */

public class HttpRequestHandler {
    private static final int CONNECTION_TIMEOUT = 20 * 1000;
    private static final int READ_TIMEOUT = 20 * 1000;

    public static String send(String urlString) throws Exception {

        final long startSendingTime = System.currentTimeMillis();
        HttpURLConnection connection = null;

        try {
            final URL url = new URL(urlString);

            connection = (HttpURLConnection) url.openConnection();

            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(READ_TIMEOUT);

            final long connectionTimeStart = System.currentTimeMillis();

            connection.connect();
            final int connectionResponse = connection.getResponseCode();

            byte[] returnCodeBytes = new byte[20];
            final int returnCodeBytesLength = connection.getInputStream().read(returnCodeBytes);
            final String returnCodeFromEngine = new String(subarray(returnCodeBytes, 0, returnCodeBytesLength));

            final long endSendingTime = System.currentTimeMillis();

            final long connectionResponseTime = endSendingTime - connectionTimeStart;


            if (connectionResponseTime > CONNECTION_TIMEOUT + READ_TIMEOUT) {
                System.out.println("Open connection time: " + connectionResponseTime);
            }

            System.out.println("URL : " + url + " response = " + connectionResponse + " took " + connectionResponseTime + " ms");

            return returnCodeFromEngine;
        } catch (Exception exception) {

            final long endSendingTime = System.currentTimeMillis();

            if (endSendingTime - startSendingTime > CONNECTION_TIMEOUT + READ_TIMEOUT) {
                System.out.println("Open connection time :" + (endSendingTime - startSendingTime) / 1000.0 + " seconds");
            }

            throw exception;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static byte[] subarray(byte[] src, int fromIndex, int toIndex) {
        byte[] result = new byte[toIndex - fromIndex];
        System.arraycopy(src, fromIndex, result, 0, toIndex - fromIndex);
        return result;
    }
}
