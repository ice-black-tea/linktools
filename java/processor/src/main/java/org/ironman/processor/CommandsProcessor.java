package org.ironman.processor;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameters;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.TypeSpec;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;

public class CommandsProcessor extends AbstractProcessor {

    @Override
    public boolean process(Set<? extends TypeElement> set, RoundEnvironment roundEnvironment) {
        final String packageName = "android.tools.processor";
        final String className = "CommandUtils";

        Set<? extends Element> elements = roundEnvironment.getElementsAnnotatedWith(Parameters.class);
        if (elements == null || elements.size() == 0) {
            return true;
        }

        MethodSpec.Builder method = MethodSpec.methodBuilder("addCommands")
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                .returns(void.class)
                .addParameter(JCommander.Builder.class, "builder");

        for (Element element : elements) {
            if (element.getKind() == ElementKind.CLASS) {
                method.addStatement("builder.addCommand(new $T())", element.asType());
            }
        }

        TypeSpec type = TypeSpec.classBuilder(className)
                .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
                .addMethod(method.build())
                .build();

        try {
            JavaFile javaFile = JavaFile.builder(packageName, type)
                    .addFileComment(" This codes are generated automatically. Do not modify!")
                    .build();
            processingEnv.getMessager().printMessage(Diagnostic.Kind.NOTE, javaFile.toString());
            javaFile.writeTo(processingEnv.getFiler());
        } catch (IOException e) {
            processingEnv.getMessager().printMessage(Diagnostic.Kind.WARNING, e.getMessage());
        }

        return true;
    }

    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        HashSet<String> set = new HashSet<>();
        set.add(Parameters.class.getCanonicalName());
        return set;
    }
}
