package org.ironman.ui;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.tools.Main;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Main.main(new String[] { "" });
    }
}
