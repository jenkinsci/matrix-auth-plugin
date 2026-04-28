package org.jenkinsci.plugins.matrixauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.jvnet.hudson.test.LogRecorder.recorded;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.FreeStyleProject;
import hudson.security.ACL;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.Permission;
import hudson.util.XStream2;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Level;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.Authentication;

@WithJenkins
class Security3676Test {

    private JenkinsRule j;

    private final LogRecorder logger = new LogRecorder();

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    public static class RandomClass {
        public static volatile boolean instantiated = false;

        public RandomClass() {
            instantiated = true;
        }
    }

    public static class InheritanceStrategyWithoutNoArgConstructor extends InheritanceStrategy {
        public static volatile boolean instantiated = false;

        public InheritanceStrategyWithoutNoArgConstructor(String requiredParam) {
            instantiated = true;
        }

        @Override
        protected boolean hasPermission(
                @NonNull Authentication a, @NonNull Permission permission, ACL child, ACL parent, ACL root) {
            return false;
        }
    }

    public static class ValidCustomInheritanceStrategy extends InheritanceStrategy {
        public static volatile boolean instantiated = false;

        public ValidCustomInheritanceStrategy() {
            instantiated = true;
        }

        @Override
        protected boolean hasPermission(
                @NonNull Authentication a, @NonNull Permission permission, ACL child, ACL parent, ACL root) {
            return false;
        }
    }

    @Test
    void testRejectArbitraryClass() {
        RandomClass.instantiated = false;

        logger.record(AbstractAuthorizationPropertyConverter.class.getName(), Level.INFO)
                .capture(100);

        String xml = getXmlSnippet(RandomClass.class);

        XStream2 xstream = new XStream2();
        AuthorizationMatrixProperty property = (AuthorizationMatrixProperty)
                xstream.fromXML(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        assertThat(RandomClass.instantiated, is(false));
        assertThat(property.getInheritanceStrategy(), instanceOf(InheritParentStrategy.class));

        assertThat(
                logger,
                recorded(containsString(String.format(
                        "Failed to parse inheritanceStrategy: Class %s does not extend InheritanceStrategy",
                        RandomClass.class.getName()))));
    }

    @Test
    void testRejectClassWithoutNoArgConstructor() {
        InheritanceStrategyWithoutNoArgConstructor.instantiated = false;

        logger.record(AbstractAuthorizationPropertyConverter.class.getName(), Level.INFO)
                .capture(100);

        String xml = getXmlSnippet(InheritanceStrategyWithoutNoArgConstructor.class);

        XStream2 xstream = new XStream2();
        AuthorizationMatrixProperty property = (AuthorizationMatrixProperty)
                xstream.fromXML(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        assertThat(InheritanceStrategyWithoutNoArgConstructor.instantiated, is(false));
        assertThat(property.getInheritanceStrategy(), instanceOf(InheritParentStrategy.class));

        assertThat(
                logger,
                recorded(containsString(String.format(
                        "Failed to parse inheritanceStrategy: Class %s does not have a parameterless constructor",
                        InheritanceStrategyWithoutNoArgConstructor.class.getName()))));
    }

    @Test
    void testRejectNonExistentClass() {
        logger.record(AbstractAuthorizationPropertyConverter.class.getName(), Level.INFO)
                .capture(100);

        String xml = getXmlSnippet("com.example.NonExistentClass");

        XStream2 xstream = new XStream2();
        AuthorizationMatrixProperty property = (AuthorizationMatrixProperty)
                xstream.fromXML(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        assertThat(property.getInheritanceStrategy(), instanceOf(InheritParentStrategy.class));
        assertThat(logger, recorded(containsString("Failed to set inheritance strategy")));
    }

    @Test
    void testAcceptValidInheritanceStrategy() throws Exception {
        ValidCustomInheritanceStrategy.instantiated = false;

        String xml = getXmlSnippet(ValidCustomInheritanceStrategy.class);

        XStream2 xstream = new XStream2();
        AuthorizationMatrixProperty property = (AuthorizationMatrixProperty)
                xstream.fromXML(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        assertThat(ValidCustomInheritanceStrategy.instantiated, is(true));
        assertThat(property.getInheritanceStrategy(), instanceOf(ValidCustomInheritanceStrategy.class));
    }

    @Test
    void testAcceptBuiltInInheritanceStrategies() {
        final List<Class<? extends InheritanceStrategy>> builtInStrategies =
                List.of(NonInheritingStrategy.class, InheritParentStrategy.class, InheritGlobalStrategy.class);

        for (Class<? extends InheritanceStrategy> strategy : builtInStrategies) {
            String xml = String.format(
                    "<hudson.security.AuthorizationMatrixProperty>\n"
                            + "  <inheritanceStrategy class=\"%s\"/>\n"
                            + "</hudson.security.AuthorizationMatrixProperty>",
                    strategy.getName());

            XStream2 xstream = new XStream2();
            AuthorizationMatrixProperty property = (AuthorizationMatrixProperty)
                    xstream.fromXML(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

            assertThat(property.getInheritanceStrategy(), instanceOf(strategy));
        }
    }

    @Test
    void testRoundTripSerialization() throws Exception {
        // Verify that legitimate usage (serialize and deserialize) still works
        FreeStyleProject project = j.createFreeStyleProject();
        AuthorizationMatrixProperty property =
                new AuthorizationMatrixProperty(java.util.Collections.emptyMap(), new NonInheritingStrategy());
        project.addProperty(property);
        project.save();

        // Reload the project
        j.jenkins.reload();

        FreeStyleProject reloadedProject = j.jenkins.getItemByFullName(project.getName(), FreeStyleProject.class);
        assertThat(reloadedProject, not(nullValue()));

        AuthorizationMatrixProperty reloadedProperty = reloadedProject.getProperty(AuthorizationMatrixProperty.class);
        assertThat(reloadedProperty, not(nullValue()));
        assertThat(reloadedProperty.getInheritanceStrategy(), not(nullValue()));
        assertThat(reloadedProperty.getInheritanceStrategy(), instanceOf(NonInheritingStrategy.class));
    }

    @NonNull
    private static String getXmlSnippet(@NonNull Class<?> clazz) {
        return getXmlSnippet(clazz.getName());
    }

    @NonNull
    private static String getXmlSnippet(@NonNull String className) {
        return String.format(
                "<hudson.security.AuthorizationMatrixProperty>\n"
                        + "  <inheritanceStrategy class=\"%s\"/>\n"
                        + "</hudson.security.AuthorizationMatrixProperty>",
                className);
    }
}
