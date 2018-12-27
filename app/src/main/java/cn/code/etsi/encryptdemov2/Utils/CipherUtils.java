package cn.code.etsi.encryptdemov2.Utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.support.annotation.Nullable;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import cn.code.etsi.encryptdemov2.R;

public class CipherUtils {
    private static CipherUtils cipherUtils;
    private final static String SHA1PRNG = "SHA1PRNG";

    private static String pubKey  ;
    private static String privateKey;
    private static byte[] prefix;
    private int id;
    private Context context;
    private  static int maxDoFinalLen = 0;

    //测试
    private String beforeEnc;
    private String afterEnc;

    private String sessionKeyBeforeEnc;
    private String sessionKeyAfterEnc;

    public synchronized static  CipherUtils getInstance(){
        if(cipherUtils == null){
            cipherUtils = new CipherUtils( );
        }
        //测试
        privateKey = ContextHolder.getPrivateKey();
        pubKey = ContextHolder.getPublicKey();
        prefix = ContextHolder.getPrefix();
        maxDoFinalLen=ContextHolder.getMaxDoFinalLen();
        return cipherUtils;
    }

    private CipherUtils(){

    }

    public void setId(int id){
        this.id = id;
    }


    public CipherUtils buildKey(long toId){
        return cipherUtils;
    }


    public byte[] encyrptByte(byte [] content){
        byte [] cache = null;;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        String sessionKey = getSessionKey();

        sessionKeyBeforeEnc = sessionKey;

        Cipher cipher = initAESCipher(sessionKey,Cipher.ENCRYPT_MODE);
        byte [] encryptedSessionKey = encryptSessionKey2byte(sessionKey);

        try{
            out.write(prefix,0,prefix.length);
            out.write(encryptedSessionKey,0,encryptedSessionKey.length);
            if(content.length<maxDoFinalLen){
                cache = cipher.doFinal(content);
                out.write(cache, 0, cache.length);
            }else{
                byte[] maxLen = new byte[maxDoFinalLen];
                byte[] remain = new byte[content.length - (content.length/maxDoFinalLen)*maxDoFinalLen];
                int inputLen = content.length;
                int length,i= 0;

                while(inputLen > 0){
                    if (inputLen > maxDoFinalLen){
//                        length = cipher.update(content,i*maxDoFinalLen,(i+1)*maxDoFinalLen,maxLen);
//                        out.write(maxLen,0,length);
                         System.arraycopy(content,i*maxDoFinalLen,maxLen,0,maxDoFinalLen);
                       cache = cipher.update(maxLen);
                    }else{
                        System.arraycopy(content,i*maxDoFinalLen,remain,0,remain.length);
                        cache = cipher.doFinal(remain,0,remain.length);
                        out.write(cache,0,cache.length);
                        System.out.print("hah");
                    }
                    inputLen -= maxDoFinalLen;
                    i+=1;
                }
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return encryptedData;
        } catch (IllegalBlockSizeException |BadPaddingException |IOException e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }

    public byte[] encryptText2byte(String content, long toId){
        setPubKey(toId);
        return encryptText2Byte(content);
    }


    public String encryptText2Str(String content) {
       String sessionKey = getSessionKey();
       sessionKeyBeforeEnc = sessionKeyBeforeEnc;
        try{
            Cipher cipher = initAESCipher(sessionKey,Cipher.ENCRYPT_MODE);
            String encryptedKey = encryptSessionKey2str(sessionKey);
            byte[] byteContent = content.getBytes("utf-8");
            return  encryptedKey + parseByte2HexStr(cipher.doFinal(byteContent));

        }catch  ( UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] encryptText2Byte(String content){
        String sessionKey = getSessionKey();

        sessionKeyBeforeEnc = sessionKey;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte [] outBytes;
        try{
            Cipher cipher = initAESCipher(sessionKey,Cipher.ENCRYPT_MODE);
            byte[] encryptedKey = encryptSessionKey2byte(sessionKey);
            byte[] byteContent = content.getBytes("utf-8");
           outBytes = cipher.doFinal(byteContent);
           out.write(encryptedKey,0,encryptedKey.length);
           out.write(outBytes,0,outBytes.length);
           return out.toByteArray();
        }catch  ( UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }


    public String decryptText2Str(String content){
            String sessionKey = content.substring(0,256);
            String payload = content.substring(256,content.length());
            String key = decryptSessionKey(sessionKey);
           sessionKeyAfterEnc = key;
            Cipher cipher = initAESCipher(key,Cipher.DECRYPT_MODE);
         try{

            byte[] byteContent = parseHexStr2Byte(payload);
            if (byteContent == null){
                return null;
            }
            return new String(cipher.doFinal(byteContent));
        }catch(BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }
    public byte[] decryptText2Bytes(byte[] byteContent){

        return decryptByte(byteContent,256,1);
    }


    public byte[] decryptFile2Bytes(byte[] byteContent){
        return decryptByte(byteContent,128,0);
    }

    /**
     *
     *  加密后，encryptedSessionKey转化为128个字节
     * @param byteContent
     * @return
     */
    public byte[] decryptByte(byte[] byteContent,int keyPos, int type){
        try{
            byte [] cache;
            byte[] verifyPrefix = new byte[prefix.length];
            byte[] key = new byte[keyPos];
            byte [] content = new byte[byteContent.length -keyPos-prefix.length] ;
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            if (byteContent.length == 0){
                return null;
            }
            //加密后的sessionKey长度，为128字节
            System.arraycopy(byteContent,0,verifyPrefix,0,prefix.length);
            if (!new String(verifyPrefix).equals(ContextHolder.getContext().getString(R.string.encryptPrefix))){
                Log.e("encrypt error","encryptPrefix not right");
                return null;
            }
            System.arraycopy(byteContent,prefix.length,key,0,key.length);
            System.arraycopy(byteContent,key.length+prefix.length,content,0,content.length);
            String sessionKey;
            if (type==0){
                sessionKey = decryptSessionKeyFile(key);
            }else
                sessionKey = decryptSessionKeyText(key);

            Cipher cipher = initAESCipher(sessionKey,Cipher.DECRYPT_MODE);
            try{
                  if (content.length <maxDoFinalLen){
                      cache =cipher.doFinal(content);
                      out.write(cache, 0, cache.length);
                  }else{
                      byte[] maxLen = new byte[maxDoFinalLen];
                      byte[] remain = new byte[content.length - (content.length/maxDoFinalLen)*maxDoFinalLen];
                      int inputLen = content.length;
                      int length,i= 0;
                      while(inputLen > 0){
                          if (inputLen >= maxDoFinalLen){
//
//                              length = cipher.update(content,i*maxDoFinalLen,(i+1)*maxDoFinalLen,maxLen);
//                              out.write(maxLen,0,length);
                               System.arraycopy(content,i*maxDoFinalLen,maxLen,0,maxDoFinalLen);
                               cache = cipher.update(maxLen);
                          }else{
                              System.arraycopy(content,i*maxDoFinalLen,remain,0,remain.length);
                              cache = cipher.doFinal(remain);
                          }
                          out.write(cache,0,cache.length);
                          inputLen -= maxDoFinalLen;
                          i+=1;
                      }
                  }
                    byte[] decryptedData = out.toByteArray();
                    out.close();
                    return decryptedData;
                }
                catch (IllegalBlockSizeException |BadPaddingException |IOException e){
                Log.e("encrypt error",e.toString());
                return null;
            }
        }catch (Exception e){
            Log.e("decrypt error",e.toString());
            return null;
        }
    }

    private String getSessionKey(){
        String base = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+~";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    /**
     *
     * @param sessionKey
     * @return 返回长度为256字节的字节数组
     */
    private byte[] encryptSessionKey2byte(String sessionKey){

        try{
            byte[] sKey = sessionKey.getBytes("utf-8");
            return    RSAUtils.rsa(sKey,privateKey,RSAUtils.RSA_PRIVATE_ENCRYPT);
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }

    /**
     *
     * @param sessionKey
     * @return 返回长度为256个字符的字符串
     */

    private String encryptSessionKey2str(String sessionKey){
        try{
            byte[] encryptedKey = RSAUtils.rsa(sessionKey.getBytes("utf-8"),privateKey,RSAUtils.RSA_PRIVATE_ENCRYPT);
            return parseByte2HexStr(encryptedKey);
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }


    /**
     * 接收端收到的数据为字节流
     * 解密sessionKey都返回字符串，用于InitAES初始化返回cipher。
     * @param sessionKey
     * @return
     */
    private String decryptSessionKeyFile(byte[] sessionKey){
//        byte[] key = parseHexStr2Byte(new String(sessionKey));
        try{
            byte[] encryptedKey = RSAUtils.rsa(sessionKey,pubKey,RSAUtils.RSA_PUBLIC_DECRYPT);
            return  new String(encryptedKey);
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }

    private String decryptSessionKeyText(byte[] sessionKey){
        byte[] key = parseHexStr2Byte(new String(sessionKey));
        try{
            byte[] encryptedKey = RSAUtils.rsa(key,pubKey,RSAUtils.RSA_PUBLIC_DECRYPT);
            return  new String(encryptedKey);
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }
    /**
     * 用于解密文本发送前内容的场景，输入的encrypedSessionKey为字符串
     * @param sessionKey
     * @return
     */
    private String decryptSessionKey(String sessionKey){

        byte [] tmp = parseHexStr2Byte(sessionKey);
        try{
            byte[] encryptedKey = RSAUtils.rsa(tmp,pubKey,RSAUtils.RSA_PUBLIC_DECRYPT);
            return  new String(encryptedKey);
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }

    public byte[] encryptFileInputStream(InputStream in, long toId){
        setPubKey(id);
        return encryptFileInputStream(in);
    }


    public byte[] encryptFileInputStream(InputStream in){
        byte[] outBytes = null;
        if(context == null)
            context = ContextHolder.getContext();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String sessionKey = getSessionKey();
        sessionKeyBeforeEnc = sessionKey;
        System.out.println(sessionKeyBeforeEnc);
        Cipher cipher = initAESCipher(sessionKey, Cipher.ENCRYPT_MODE);
        byte[] keyBytes = encryptSessionKey2byte(sessionKey);
        out.write(prefix,0,prefix.length);
        out.write(keyBytes,0,keyBytes.length);
        try{
         int inputLen  = in.available();
         if (inputLen < maxDoFinalLen ){
             byte [] tmp = new byte[in.available()];
             beforeEnc = new String(tmp);
             in.read(tmp);
             outBytes =cipher.doFinal(tmp);
             out.write(outBytes,0,outBytes.length);
         }else{
             boolean more = true;
              int readLen=0;
              byte inBytes[] = new byte[maxDoFinalLen];
             while (more) {
                 readLen = in.read(inBytes);
                 if (readLen == maxDoFinalLen) {
                     outBytes = cipher.update(inBytes);
                    out.write(outBytes,0,outBytes.length);
                 } else {
                     more = false;
                 }
             }
             outBytes = cipher.doFinal(inBytes,0,readLen);
             out.write(outBytes,0,outBytes.length);
         }
         return out.toByteArray();
        }catch (Exception e){
            Log.e("encrypt error",e.toString());
            return null;
        }
    }

    public byte[] decryptFileInputStream(InputStream in){
        byte[] outBytes = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] encPrefix = new byte[prefix.length];
        byte[] skey = new byte[128];
        try{
            if((in.read(encPrefix)) ==-1 || !context.getString(R.string.encryptPrefix).equals(new String(encPrefix))){
                return null;
            }
            if ((in.read(skey)== -1)){
                return null;
            }
            String sessionKey =  decryptSessionKeyFile(skey);

            sessionKeyAfterEnc = sessionKey;

            Cipher cipher = initAESCipher(sessionKey,Cipher.DECRYPT_MODE);
            int inputLen  = in.available() - 128 - encPrefix.length;
            if (inputLen < maxDoFinalLen ){
                byte [] tmp = new byte[in.available()];
                in.read(tmp);
                outBytes =cipher.doFinal(tmp);
                out.write(outBytes,0,outBytes.length);
            }else{
                boolean more = true;
                int readLen=0;
                byte inBytes[] = new byte[maxDoFinalLen];
                while (more) {
                    readLen = in.read(inBytes);
                    if (readLen == maxDoFinalLen) {
                        outBytes = cipher.update(inBytes);
                        out.write(outBytes,0,outBytes.length);
                    } else {
                        more = false;
                    }
                }
                outBytes = cipher.doFinal(inBytes,0,readLen);
                out.write(outBytes,0,outBytes.length);
            }
            byte[] ret = out.toByteArray();
            afterEnc = new String(ret);
            return out.toByteArray();
        }catch (Exception e){
            return null;
        }
    }


    public File encryptFile(File sourceFile, String toFile, String dir, String sKey) {
        // 新建临时加密文件
        File encrypfile = null;
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            inputStream = new FileInputStream(sourceFile);
            encrypfile = new File(dir + toFile);
            outputStream = new FileOutputStream(encrypfile);
            Cipher cipher = initAESCipher(sKey, Cipher.ENCRYPT_MODE);
            // 以加密流写入文件
            CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
            byte[] cache = new byte[1024];
            int nRead = 0;
            while ((nRead = cipherInputStream.read(cache)) != -1) {
                outputStream.write(cache, 0, nRead);
                outputStream.flush();
            }
            cipherInputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return encrypfile;
    }

    /**
     * AES方式解密文件
     * @param sourceFile
     * @return
     */
    public File decryptFile(File sourceFile, String toFile, String dir, String sKey) {
        File decryptFile = null;
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            decryptFile = new File(dir + toFile);
            Cipher cipher = initAESCipher(sKey, Cipher.DECRYPT_MODE);
            inputStream = new FileInputStream(sourceFile);
            outputStream = new FileOutputStream(decryptFile);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            byte[] buffer = new byte[1024];
            int r;
            while ((r = inputStream.read(buffer)) >= 0) {
                cipherOutputStream.write(buffer, 0, r);
            }
            cipherOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return decryptFile;
    }

    @Nullable
    private Cipher initAESCipher(String passwd, int mode) {

        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");

            SecureRandom secureRandom;
            if (android.os.Build.VERSION.SDK_INT >= 24) {
                secureRandom = SecureRandom.getInstance(SHA1PRNG, new CryptoProvider());
            } else {
                secureRandom = SecureRandom.getInstance(SHA1PRNG);
            }
            secureRandom.setSeed(passwd.getBytes());
            generator.init(128, secureRandom);
            SecretKey secretKey = generator.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("AES/ECB/ZeroBytePadding");
            cipher.init(mode, key);
            return cipher;
        }catch (NoSuchAlgorithmException | NoSuchPaddingException |InvalidKeyException e){
            return null;
        }

    }

    private static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) return null;
        byte[] result = new byte[hexStr.length() / 2];

        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    private static String parseByte2HexStr(byte buf[]) {
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    private void setPubKey(long id){


    }

}
