package RSAdigitalsignal;
import java.util.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import  org.apache.commons.codec.binary.Hex;

public class RSAUtil {
    /**
     * 生成公钥和私钥
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static HashMap<String,Object> getKey(){
        HashMap<String,Object> map = new HashMap<String,Object>();
        KeyPairGenerator generator = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        }catch (Exception e){
            return null;
        }
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();  //赋予公钥public属性
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();  //赋予私钥private属性
        map.put("pubKey",rsaPublicKey);     //将生成的私钥和秘钥加入哈希表
        map.put("priKey",rsaPrivateKey);
        return map;
    }
    /**
     * 私密加密
     * @param data        声明参数
     * @param priKey
     * @return
     * @throws Exception
     */
     public static String encryptByPriKey(String data,RSAPrivateKey priKey){
         PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(priKey.getEncoded());
         KeyFactory keyFactory;
         PrivateKey key;
         Signature sign;    //定义数字签名
         byte[] result = null;  //将结果存放到数组
         try {
             keyFactory = KeyFactory.getInstance("RSA");    //返回转换指定算法的 public/private 关键字的 KeyFactory 对象
             key = keyFactory.generatePrivate(keySpec);     //根据提供的密钥规范（密钥材料）生成私钥对象。
             sign = Signature.getInstance("MD5withRSA");    //返回指定算法的签名
             sign.initSign(key);        //初始化这个用于签名的对象
             sign.update(data.getBytes());  //处理的内容
             result = sign.sign();      //返回所有已更新数据的签名字节
         }catch (Exception e)
         {
             e.printStackTrace();
         }
         System.out.println("rsa sign:"+Hex.encodeHexString(result));
         System.out.println("sign len:"+result.length+",str hex:"+Hex.encodeHexString(result).length());
         return Hex.encodeHexString(result);
     }
    /**
     * 公钥验证
     * @param data
     * @param pubKey
     * @param res
     * @return
     * @throws Exception
     */
    public static boolean decryptByPubKey(String data,RSAPublicKey pubKey,String res){
        System.out.println("res len"+res.length());
        X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(pubKey.getEncoded());
        KeyFactory keyFactory;
        PublicKey key;
        Signature sign;
        boolean result = false;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePublic(x509keySpec);
            sign = Signature.getInstance("MD5withRSA");
            sign.initVerify(key);       //初始化此用于验证的对象
            sign.update(data.getBytes());   //更新要由字节签名或验证的数据
            result = sign.verify(Hex.decodeHex(res.toCharArray()));
            //验证传入的签名
        }catch (Exception e)
        {
            e.printStackTrace();
        }
        System.out.println("rsa verify:"+result);
        return result;
    }
}
