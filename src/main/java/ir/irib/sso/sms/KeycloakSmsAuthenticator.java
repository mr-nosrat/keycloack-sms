package ir.irib.sso.sms;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Random;


import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.XMLType;

import javax.xml.namespace.QName;
import javax.xml.rpc.ParameterMode;


/**
 * Created by joris on 11/11/2016.
 */

public class KeycloakSmsAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(KeycloakSmsAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "sms_validation";

    private static enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }


    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate called ... context = " + context);

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        String mobileNumberAttribute = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_USR_ATTR_MOBILE);
        if (mobileNumberAttribute == null) {
            logger.error("Mobile number attribute is not configured for the SMS Authenticator.");
            Response challenge = context.form()
                    .setError("Mobile number can not be determined.")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
            return;
        }

        String mobileNumber = SMSAuthenticatorUtil.getAttributeValue(context.getUser(), mobileNumberAttribute);
        if (mobileNumber != null) {
            // The mobile number is configured --> send an SMS


            long nrOfDigits = SMSAuthenticatorUtil.getConfigLong(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CODE_LENGTH, 8L);
            logger.debug("Using nrOfDigits " + nrOfDigits);


            long ttl = SMSAuthenticatorUtil.getConfigLong(config, SMSAuthenticatorContstants.CONF_PRP_SMS_CODE_TTL, 10 * 60L); // 10 minutes in s

            logger.debug("Using ttl " + ttl + " (s)");

            String code = getSmsCode(nrOfDigits);

            storeSMSCode(context, code, new Date().getTime() + (ttl * 1000)); // s --> ms
//            if (sendSmsCode(mobileNumber, code, context.getAuthenticatorConfig())) {
            if (sendSMS(mobileNumber, code, context.getAuthenticatorConfig())) {
                Response challenge = context.form().createForm("sms-validation.ftl");
                context.challenge(challenge);
            } else {
                Response challenge = context.form()
                        .setError("SMS could not be sent.")
                        .createForm("sms-validation-error.ftl");
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                return;
            }
        } else {
            // The mobile number is NOT configured --> complain
            Response challenge = context.form()
                    .setError("Missing mobile number")
                    .createForm("sms-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
            return;
        }
    }


    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);
        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                challenge = context.form()
                        .setError("code is expired")
                        .createForm("sms-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;

            case INVALID:
                if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.OPTIONAL ||
                        context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.debug("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    challenge = context.form()
                            .setError("badCode")
                            .createForm("sms-validation.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    // Something strange happened
                    logger.warn("Undefined execution ...");
                }
                break;

            case VALID:
                context.success();
                break;

        }
    }

    SmsCodeModel smsCodeModel;

    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private void storeSMSCode(AuthenticationFlowContext context, String code, Long expiringAt) {
        try {
            UserCredentialModel credentials = new UserCredentialModel();
            credentials.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
            credentials.setValue(code);
//            context.getSession().users().updateCredential(context.getRealm(), context.getUser(), credentials);

            credentials.setType(SMSAuthenticatorContstants.USR_CRED_MDL_SMS_EXP_TIME);
            credentials.setValue((expiringAt).toString());

            smsCodeModel = new SmsCodeModel(context.getUser().getId(), code, expiringAt);
//            context.getSession().users().updateCredential(context.getRealm(), context.getUser(), credentials);
        } catch (Exception e) {
            e.printStackTrace();

        }
    }


    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(SMSAuthenticatorContstants.ANSW_SMS_CODE);

        String expectedCode = smsCodeModel.getSmsCode();// SMSAuthenticatorUtil.getCredentialValue(context.getUser(), SMSAuthenticatorContstants.USR_CRED_MDL_SMS_CODE);
        Long expTimeString = smsCodeModel.getExpiredTime();//  SMSAuthenticatorUtil.getCredentialValue(context.getUser(), SMSAuthenticatorContstants.USR_CRED_MDL_SMS_EXP_TIME);

        logger.debug("Expected code = " + expectedCode + "    entered code = " + enteredCode);

        if (expectedCode != null) {
            result = enteredCode.equals(expectedCode) ? CODE_STATUS.VALID : CODE_STATUS.INVALID;
            long now = new Date().getTime();

            logger.debug("Valid code expires in " + (expTimeString - now) + " ms");
            if (result == CODE_STATUS.VALID) {
                if (expTimeString < now) {
                    logger.debug("Code is expired !!");
                    result = CODE_STATUS.EXPIRED;
                }
            }
        }
        logger.debug("result : " + result);
        return result;
    }

    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        boolean result = true;
        logger.debug("... returning " + result);
        return result;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("setRequiredActions called ... session=" + session + ", realm=" + realm + ", user=" + user);
    }

    public void close() {
        logger.debug("close called ...");
    }


    private String getSmsCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }

        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    public boolean sendSMS1(String mobileNo, String message) {
        final String END_POINT_URL = "http://sms.magfa.com/magfaHttpService?";
        final String METHOD_CALL = "enqueue";

        final String USER_NAME = "majazi"; //fill this with your username
        final String PASSWORD = "ucJiFNlokfySUsNq";  //fill this with your password
        final String SENDER_NUMBER = "30007620"; //your 3000xxxxx number
        final String RECIPIENT_NUMBER = mobileNo; //the phone number you wish to send something to...
        final String DOMAIN = "irib";    //fill this with your domain

        final String MESSGAE_TEXT = message;
        final String UDH = "";       //can be left blank
        final String ENCODING = "";  //encoding of the message. if left blank, system will guess the message encoding automatically
        final String CHECKING_MESSAGE_ID = "";   //can be left blank


        try {
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

            final Long response = Long.parseLong(HttpRequestHandler.send(sb.toString()));
            if (response <= ErrorCodes.MAX_VALUE) {
                System.out.println("error occurred, code: " + response + ", " + ErrorCodes.getDescriptionForCode(response.intValue()));
                return false;
            } else {
                System.out.println("Submitted successfully, messageId: " + response);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    public boolean sendSMS(String mobileNo, String message, AuthenticatorConfigModel config) {

        int parameterCount = 1;   //specifies how many requests are to be made

//        final String END_POINT_URL = "http://sms.magfa.com/services/urn:SOAPSmsQueue";
        final String URN = "urn:SOAPSmsQueue";
        final String ENQUEUE_METHOD_CALL = "enqueue";

        String RECIPIENT_NUMBER = mobileNo;
        String DOMAIN = "sinet";

        String END_POINT_URL = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_URL);
        String USER_NAME = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_USERNAME);
        String PASSWORD = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_PASSWORD);
        String SENDER_NUMBER = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_SENDER);
        String SMS_TEXT = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TEXT);

        message = SMS_TEXT.replace("%sms-code%", message);

//        SENDER_NUMBER = "30007620"; //fill this with a number from your accounts's number range

        try {
            //creating a service object
            Service service = new Service();
            //creating a call object from the service and setting it's basic properties
            Call call = (Call) service.createCall();
            call.setTargetEndpointAddress(new URL(END_POINT_URL));
            call.setOperationName(new QName(URN, ENQUEUE_METHOD_CALL));
            call.setUsername(USER_NAME);
            call.setPassword(PASSWORD);
            call.setReturnType(XMLType.SOAP_ARRAY);
            call.setTimeout(10 * 60 * 1000);
            //defining the parameters the service accepts
            call.addParameter("domain", XMLType.SOAP_STRING, ParameterMode.IN);
            call.addParameter("messages", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("recipientNumbers", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("senderNumbers", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("encodings", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("udhs", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("messageClasses", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("priorities", XMLType.SOAP_ARRAY, ParameterMode.IN);
            call.addParameter("checkingMessageIds", XMLType.SOAP_ARRAY, ParameterMode.IN);

            String domain;
            String[] messages;
            String[] recipientNumbers;
            String[] senderNumbers;
            int[] encodings;
            String[] udhs;
            Integer[] mClass;
            Integer[] priorities;
            long[] checkingMessageIds;

            domain = DOMAIN;
            messages = new String[parameterCount];
            recipientNumbers = new String[parameterCount];
            senderNumbers = new String[parameterCount];
            encodings = new int[parameterCount];
            udhs = null;
            mClass = null;
            priorities = null;
            checkingMessageIds = new long[parameterCount];

            for (int i = 0; i < parameterCount; i++) {
                recipientNumbers[i] = RECIPIENT_NUMBER;
                senderNumbers[i] = SENDER_NUMBER;
                checkingMessageIds[i] = i + 10L;
                messages[i] = message;
                encodings[i] = -1;
            }
            //preparing the inputs for calling the service
            Object[] params = {domain, messages, recipientNumbers, senderNumbers, encodings, udhs, mClass, priorities, checkingMessageIds};
            //preparing the object array to be filled as output values
            Object[] returnArray = null;

            try {
                double startTime = System.currentTimeMillis();
                //making the request
                returnArray = (Object[]) call.invoke(params);
                System.out.println("request response-time=" + (System.currentTimeMillis() - startTime) / 1000 + " sec.s");
            } catch (Exception exception) {
                exception.printStackTrace();
                return false;
            }
            //print out the results
            if (returnArray != null) {
                for (int i = 0; i < returnArray.length; i++) {
                    final long returnValue = (Long) returnArray[i];
                    if (returnValue < ErrorCodes.WEB_SENDER_NUMBER_ARRAY_IS_NULL.getCode()) {
                        System.out.println("caught error: " + returnValue + ", " + ErrorCodes.getDescriptionForCode((int) returnValue));
                        return false;
                    } else {
                        System.out.println("returnArray index " + i + " = " + returnValue);
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
        return true;

    }

    private boolean sendSmsCode(String mobileNumber, String code, AuthenticatorConfigModel config) {
        // Send an SMS
        logger.debug("Sending " + code + "  to mobileNumber " + mobileNumber);

        String smsUrl = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_URL);
        String smsUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_USERNAME);
        String smsPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_PASSWORD);

        String proxyUrl = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_URL);
        String proxyUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_USERNAME);
        String proxyPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_PROXY_PASSWORD);
        String contentType = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_CONTENT_TYPE);

        CloseableHttpClient httpClient = null;
        try {
            URL smsURL = (smsUrl != null && smsUrl.length() > 0) ? new URL(smsUrl) : null;
            URL proxyURL = (proxyUrl != null && proxyUrl.length() > 0) ? new URL(proxyUrl) : null;

            if (smsURL == null) {
                logger.error("SMS gateway URL is not configured.");
                return false;
            }


            CredentialsProvider credsProvider;
//            if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.AUTH_METHOD_INMESSAGE)) {
//                credsProvider = getCredentialsProvider(null, null, proxyUsr, proxyPwd, smsURL, proxyURL);
//            } else
            {
                credsProvider = getCredentialsProvider(smsUsr, smsPwd, proxyUsr, proxyPwd, smsURL, proxyURL);
            }

            HttpHost target = new HttpHost(smsURL.getHost(), smsURL.getPort(), smsURL.getProtocol());
            HttpHost proxy = (proxyURL != null) ? new HttpHost(proxyURL.getHost(), proxyURL.getPort(), proxyURL.getProtocol()) : null;

            httpClient = HttpClients.custom()
                    .setDefaultCredentialsProvider(credsProvider)
                    .build();

            RequestConfig requestConfig;
            requestConfig = RequestConfig.custom()
                    .setProxy(proxy)
                    .build();

            String httpMethod = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_METHOD);
            String smsText = createMessage(code, mobileNumber, config);
//            if(httpMethod.equals(HttpMethod.GET)) {
//
//                String path = getPath(mobileNumber, smsURL, smsText);
//
//                HttpGet httpGet = new HttpGet(path);
//                httpGet.setConfig(requestConfig);
//                if(isNotEmpty(contentType)) {
//                    httpGet.addHeader("Content-type", contentType);
//                }
//
//                logger.debug("Executing request " + httpGet.getRequestLine() + " to " + target + " via " + proxy);
//
//                CloseableHttpResponse response = httpClient.execute(target, httpGet);
//                StatusLine sl = response.getStatusLine();
//                response.close();
//                if(sl.getStatusCode() != 200) {
//                    logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() +  " - " + sl.getReasonPhrase());
//                }
//                return sl.getStatusCode() == 200;
//
//            } else if (httpMethod.equals(HttpMethod.POST))
            {

                String path = getPath(mobileNumber, smsURL, smsText);
                String uri = smsURL.getProtocol() + "://" + smsURL.getHost() + ":" + smsURL.getPort() + path;

                HttpPost httpPost = new HttpPost(uri);
                httpPost.setConfig(requestConfig);
                if (isNotEmpty(contentType)) {
                    httpPost.addHeader("Content-type", contentType);
                }

                HttpEntity entity = new ByteArrayEntity(smsText.getBytes("UTF-8"));
                httpPost.setEntity(entity);

                CloseableHttpResponse response = httpClient.execute(httpPost);
                StatusLine sl = response.getStatusLine();
                response.close();
                if (sl.getStatusCode() != 200) {
                    logger.error("SMS code for " + mobileNumber + " could not be sent: " + sl.getStatusCode() + " - " + sl.getReasonPhrase());
                }
                return sl.getStatusCode() == 200;
            }
//            return true;
        } catch (IOException e) {
            logger.error(e);
            return false;
        } finally {
            if (httpClient != null) {
                try {
                    httpClient.close();
                } catch (IOException ignore) {
                    // Ignore ...
                }
            }
        }
    }


    private String getPath(String mobileNumber, URL smsURL, String smsText) throws UnsupportedEncodingException {
        String path = smsURL.getPath();
        if (smsURL.getQuery() != null && smsURL.getQuery().length() > 0) {
            path += smsURL.getQuery();
        }
        path = path.replaceFirst("\\{message\\}", URLEncoder.encode(smsText, "UTF-8"));
        path = path.replaceFirst("\\{phonenumber\\}", URLEncoder.encode(mobileNumber, "UTF-8"));
        return path;
    }

    private CredentialsProvider getCredentialsProvider(String smsUsr, String smsPwd, String proxyUsr, String proxyPwd, URL smsURL, URL proxyURL) {
        CredentialsProvider credsProvider = new BasicCredentialsProvider();

        // If defined, add BASIC Authentication parameters
        if (isNotEmpty(smsUsr) && isNotEmpty(smsPwd)) {
            credsProvider.setCredentials(
                    new AuthScope(smsURL.getHost(), smsURL.getPort()),
                    new UsernamePasswordCredentials(smsUsr, smsPwd));

        }

        // If defined, add Proxy Authentication parameters
        if (isNotEmpty(proxyUsr) && isNotEmpty(proxyPwd)) {
            credsProvider.setCredentials(
                    new AuthScope(proxyURL.getHost(), proxyURL.getPort()),
                    new UsernamePasswordCredentials(proxyUsr, proxyPwd));

        }
        return credsProvider;
    }

    private String createMessage(String code, String mobileNumber, AuthenticatorConfigModel config) {
        String text = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_TEXT);
        text = text.replaceAll("%sms-code%", code);
        text = text.replaceAll("%phonenumber%", mobileNumber);

//        if(SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_AUTHTYPE, "").equals(SMSAuthenticatorContstants.AUTH_METHOD_INMESSAGE)) {
        String smsUsr = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_USERNAME);
        String smsPwd = SMSAuthenticatorUtil.getConfigString(config, SMSAuthenticatorContstants.CONF_PRP_SMS_PASSWORD);

        text = text.replaceAll("%user%", smsUsr);
        text = text.replaceAll("%password%", smsPwd);
//        }

        return text;
    }

    private boolean isNotEmpty(String s) {
        return (s != null && s.length() > 0);
    }

}
