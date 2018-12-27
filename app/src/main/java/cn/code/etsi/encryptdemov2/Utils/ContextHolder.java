package cn.code.etsi.encryptdemov2.Utils;

import android.content.Context;

import cn.code.etsi.encryptdemov2.R;

public class ContextHolder {
   private static Context applicationContext;
   private   static String privateKey;
   private  static String publicKey;

    public static void initial(Context context){
        applicationContext = context;
        setPrivateKey();
        setPublicKey();
    }

    public static Context getContext(){
        return applicationContext;
    }

    private static void setPrivateKey(){
        privateKey = applicationContext.getString(R.string.privKey);
    }

    private static void setPublicKey(){
        publicKey = applicationContext.getString(R.string.pubKey);
    }

    public static String getPublicKey(){
       return publicKey;
    }
    public static String getPrivateKey(){
        return privateKey;
    }
    public static byte[] getPrefix(){
        return getContext().getString(R.string.encryptPrefix).getBytes();

    }

    public static int getMaxDoFinalLen(){
        return Integer.parseInt(getContext().getString(R.string.MaxDoFinalLen));
    }
}
