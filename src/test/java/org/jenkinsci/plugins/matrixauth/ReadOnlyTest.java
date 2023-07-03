package org.jenkinsci.plugins.matrixauth;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Computer;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Slave;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.io.IOException;
import java.util.Collections;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.xml.sax.SAXException;

@Issue("JENKINS-62202")
public class ReadOnlyTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static boolean containsClassName(String className, String value) {
        Objects.requireNonNull(className, "className");
        Objects.requireNonNull(value, "value");
        return value.equals(className)
                || value.startsWith(className + " ")
                || value.endsWith(" " + className)
                || value.contains(" " + className + " ");
    }

    private static boolean hasTagWithClassInPage(HtmlPage page, String tagName, String className) {
        return page.getElementsByTagName(tagName).stream()
                .anyMatch(it -> containsClassName(className, it.getAttribute("class")));
    }

    private HtmlPage initAndAssertPresent(String configurationUrl) throws IOException, SAXException {
        JenkinsRule.WebClient wc = j.createWebClient();
        final HtmlPage page = wc.goTo(configurationUrl);
        Assert.assertTrue(
                "contains permission container",
                hasTagWithClassInPage(page, "table", "global-matrix-authorization-strategy-table"));
        return page;
    }

    private void assertPresentAndEditable(String configurationUrl) throws IOException, SAXException {
        final HtmlPage page = initAndAssertPresent(configurationUrl);
        Assert.assertTrue(
                "should contain add group/user button",
                hasTagWithClassInPage(
                        page,
                        "span",
                        "matrix-auth-add-button")); // Behavior.specify / makeButton converts input to button and wraps
        // it in span
    }

    private void assertPresentAndReadOnly(String configurationUrl) throws IOException, SAXException {
        final HtmlPage page = initAndAssertPresent(configurationUrl);
        Assert.assertFalse(
                "should not contain add group/user button",
                hasTagWithClassInPage(
                        page,
                        "span",
                        "matrix-auth-add-button")); // Behavior.specify / makeButton converts input to button and wraps
        // it in span
    }

    @Before
    public void prepare() {
        Jenkins.SYSTEM_READ.enabled = true;
        Item.EXTENDED_READ.enabled = true;
        Computer.EXTENDED_READ.enabled = true;
        Jenkins.get().setSecurityRealm(j.createDummySecurityRealm());
        final ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        {
            strategy.add(Jenkins.READ, "anonymous");
            strategy.add(Jenkins.SYSTEM_READ, "anonymous");
            strategy.add(Item.READ, "anonymous");
            strategy.add(Item.EXTENDED_READ, "anonymous");
            strategy.add(Computer.EXTENDED_READ, "anonymous");
        }
        Jenkins.get().setAuthorizationStrategy(strategy);
    }

    @Test
    public void testGlobalConfiguration() throws IOException, SAXException {
        assertPresentAndReadOnly("configureSecurity");

        ((ProjectMatrixAuthorizationStrategy) Jenkins.get().getAuthorizationStrategy())
                .add(Jenkins.ADMINISTER, "anonymous");
        assertPresentAndEditable("configureSecurity");
    }

    @Test
    public void testJobConfiguration() throws IOException, SAXException {
        final FreeStyleProject job =
                j.createFreeStyleProject(); // While 2.223 changed the UI (readOnlyMode), the basic behavior by this
        // plugin remains the same due to permission check
        job.addProperty(new AuthorizationMatrixProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertPresentAndReadOnly(job.getUrl() + "configure");

        job.removeProperty(AuthorizationMatrixProperty.class);
        job.addProperty(new AuthorizationMatrixProperty(
                Collections.singletonMap(
                        Item.CONFIGURE,
                        Collections.singleton(
                                new PermissionEntry(AuthorizationType.USER, Jenkins.ANONYMOUS2.getName()))),
                new InheritParentStrategy()));
        assertPresentAndEditable(job.getUrl() + "configure");
    }

    @Test
    public void testFolderConfiguration() throws IOException, SAXException {
        final Folder folder = Jenkins.get().createProject(Folder.class, "testFolder");
        folder.addProperty(
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(Collections.emptyMap()));
        assertPresentAndReadOnly(folder.getUrl() + "configure");

        folder.getProperties()
                .replace(new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(
                        Collections.singletonMap(Item.CONFIGURE, Collections.singleton(Jenkins.ANONYMOUS2.getName()))));
        assertPresentAndEditable(folder.getUrl() + "configure");
    }

    @Test
    public void testAgentConfigurationGlobally() throws Exception {
        final Slave agent = j.createSlave();
        agent.setNodeProperties(Collections.singletonList(new AuthorizationMatrixNodeProperty()));
        assertPresentAndReadOnly("computer/" + agent.getNodeName() + "/configure");

        ((ProjectMatrixAuthorizationStrategy) Jenkins.get().getAuthorizationStrategy())
                .add(Computer.CONFIGURE, Jenkins.ANONYMOUS2.getName());
        assertPresentAndEditable("computer/" + agent.getNodeName() + "/configure");
    }

    @Test
    public void testAgentConfigurationPerAgent() throws Exception {
        final Slave agent = j.createSlave();
        agent.setNodeProperties(Collections.singletonList(new AuthorizationMatrixNodeProperty()));
        assertPresentAndReadOnly("computer/" + agent.getNodeName() + "/configure");

        final AuthorizationMatrixNodeProperty prop = new AuthorizationMatrixNodeProperty();
        prop.add(Computer.CONFIGURE, Jenkins.ANONYMOUS2.getName());
        agent.setNodeProperties(Collections.singletonList(prop));
        assertPresentAndEditable("computer/" + agent.getNodeName() + "/configure");
    }
}
