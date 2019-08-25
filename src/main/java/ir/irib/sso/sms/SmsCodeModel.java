package ir.irib.sso.sms;

public class SmsCodeModel {


    private String ID;
    private  String smsCode;
    private Long expiredTime;

    public SmsCodeModel(){

    }

    public SmsCodeModel(String ID, String smsCode, Long expiredTime) {
        this.ID = ID;
        this.smsCode = smsCode;
        this.expiredTime = expiredTime;
    }

    public String getID() {
        return ID;
    }

    public void setID(String ID) {
        this.ID = ID;
    }

    public String getSmsCode() {
        return smsCode;
    }

    public void setSmsCode(String smsCode) {
        this.smsCode = smsCode;
    }

    public Long getExpiredTime() {
        return expiredTime;
    }

    public void setExpiredTime(Long expiredTime) {
        this.expiredTime = expiredTime;
    }
}
