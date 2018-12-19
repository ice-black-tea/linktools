package android.tools;

import android.util.Log;

import java.io.PrintStream;

/**
 * Created by hu on 18-12-19.
 */

public interface Output {

    Output out = new OutputImpl(System.out);
    Output err = new OutputImpl(System.err);

    class OutputImpl implements Output {

        private PrintStream printStream = null;

        public OutputImpl(PrintStream printStream) {
            this.printStream = printStream;
        }

        @Override
        public Output print(String format, Object... args) {
            printStream.print(args.length > 0 ? String.format(format, args): args);
            return this;
        }

        @Override
        public Output println(String format, Object... args) {
            printStream.println(args.length > 0 ? String.format(format, args): args);
            return this;
        }

        @Override
        public Output println(Throwable th) {
            printStream.println(Log.getStackTraceString(th));
            return this;
        }

        @Override
        public Output println() {
            printStream.println();
            return this;
        }
    }

    Output print(String format, Object... args);
    Output println(String format, Object... args);
    Output println(Throwable th);
    Output println();
}
