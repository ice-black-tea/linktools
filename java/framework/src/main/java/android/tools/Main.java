package android.tools;

import android.tools.command.CommandActivity;
import android.tools.command.CommandMain;
import android.tools.command.CommandPackage;

import com.beust.jcommander.JCommander;

public class Main {

    private static void parseArgs(String[] args) throws Throwable {
        CommandMain commandMain = new CommandMain();
        CommandActivity commandActivity = new CommandActivity();
        CommandPackage commandPackage = new CommandPackage();
        JCommander.newBuilder()
                .addObject(commandMain)
                .addCommand("activity", commandActivity)
                .addCommand("package", commandPackage)
                .build()
                .parse(args);

        if (commandMain.help) {
            System.out.println("dsadsadsadsa");
        }
    }



    public static void main(String[] args) {
        try {
            parseArgs(args);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}
