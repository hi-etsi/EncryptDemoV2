package cn.code.etsi.encryptdemov2;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import cn.code.etsi.encryptdemov2.Utils.CipherUtils;
import cn.code.etsi.encryptdemov2.Utils.ContextHolder;


public class MainActivity extends AppCompatActivity {

    private EditText clearText;
    private EditText decryptText;
    private EditText encryptText;
    private Button  doEncrypt;
    private Button  doDecrypt;
    private boolean flag = false;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ContextHolder.initial(getApplicationContext());
        setContentView(R.layout.activity_main);


        clearText =  findViewById(R.id.editClearText);
        encryptText = findViewById(R.id.editEncrypt);
        decryptText = findViewById(R.id.editAfterDecrypt);
        doEncrypt =  findViewById(R.id.encrypt);
        doDecrypt = findViewById(R.id.decrypt);

        doEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (flag){
                    return ;
                }
               String text = clearText.getText().toString();
                String content = CipherUtils.getInstance().encryptText2Str(text);
                encryptText.setText(content);
                flag = true;
            }
        });

        doDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (!flag){
                    return;
                }
                String toDecrypt = encryptText.getText().toString();
                String content = CipherUtils.getInstance().decryptText2Str(toDecrypt);
                decryptText.setText(content);
                flag = false;
            }
        });


        Button trans2Pic = findViewById(R.id.transfer2PicActivity);
        trans2Pic.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this,PicActivity.class));
            }
        });

        Button trans2File =  findViewById(R.id.trans2File);
        trans2File.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this,FileActivity.class));
            }
        });
    }

}
