package RSAdigitalsignal;
import java.security.interfaces.*;
import java.util.*;

public class RSA {
    public final static String src = "hello world hello world hello world hello world hello world hello worldhello worldhello world hello world hello world hello world hello worldhello world hello world hello world hello world v hello world hello world hello world vhello world hello world";
    public final static String _src = "hello world hello world hello world hello world hello world hello worldhello worldhello world hello world hello world hello world hello worldhello world hello world hello world hello world v hello world hello world hello world vhello world hello world";
    public static void main(String []args){
        //登录rosp返回给客户端
        HashMap<String,Object> map = RSAUtil.getKey();
        RSAPublicKey pubKey = (RSAPublicKey) map.get("pubKey");
        RSAPrivateKey priKey = (RSAPrivateKey) map.get("priKey");
        //客户端get提交给服务器
        String res = RSAUtil.encryptByPriKey(src,priKey);
        //服务端验证
        RSAUtil.decryptByPubKey(_src,pubKey,res);
    }
}
