package com.alliander.keycloak.authenticator;


import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Created by IntelliJ IDEA.
 * User: amin
 * Date: Jul 6, 2010
 * Time: 11:48:39 AM
 */

public class EnqueueSample {
    private static final String END_POINT_URL = "http://sms.magfa.com/magfaHttpService?";
    private static final String METHOD_CALL = "enqueue";

    private static final String USER_NAME = "majazi"; //fill this with your username
    private static final String PASSWORD = "ucJiFNlokfySUsNq";  //fill this with your password
    private static final String SENDER_NUMBER = "30007620"; //your 3000xxxxx number
    private static final String RECIPIENT_NUMBER = "09122407967"; //the phone number you wish to send something to...
    private static final String DOMAIN = "irib";    //fill this with your domain

    private static final String MESSGAE_TEXT = "MAGFA http_enqueue test";
    private static final String UDH = "";       //can be left blank
    private static final String ENCODING = "";  //encoding of the message. if left blank, system will guess the message encoding automatically
    private static final String CHECKING_MESSAGE_ID = "";   //can be left blank

    public static void main(String[] args) {
        try {
            final String urlString = makeUrlString();
            System.out.println("<====MAGFA HTTP_SERVICE SAMPLE====>");
            System.out.println("Requesting Enqueue service from " + urlString);

            final Long response = Long.parseLong(HttpRequestHandler.send(urlString));
            if (response <= ErrorCodes.MAX_VALUE) {
                System.out.println("error occurred, code: " + response + ", " + ErrorCodes.getDescriptionForCode(response.intValue()));
            } else {
                System.out.println("Submitted successfully, messageId: " + response);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String makeUrlString() throws UnsupportedEncodingException {
        final StringBuilder sb = new StringBuilder(END_POINT_URL);
        sb.append("service=").append(METHOD_CALL).append("&");
        sb.append("username=").append(USER_NAME).append("&");
        sb.append("password=").append(PASSWORD).append("&");
        sb.append("from=").append(SENDER_NUMBER).append("&");
        sb.append("to=").append(RECIPIENT_NUMBER).append("&");
        sb.append("domain=").append(DOMAIN).append("&");
        sb.append("message=").append(URLEncoder.encode(MESSGAE_TEXT, "ISO-8859-1")).append("&");
        sb.append("udh=").append(UDH).append("&");
        sb.append("coding=").append(ENCODING).append("&");
        sb.append("chkmessageid=").append(CHECKING_MESSAGE_ID);

        return sb.toString();
    }
}
