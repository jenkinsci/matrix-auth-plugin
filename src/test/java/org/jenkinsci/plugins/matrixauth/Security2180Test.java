package org.jenkinsci.plugins.matrixauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Cause;
import hudson.model.Executor;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.TopLevelItem;
import hudson.model.TopLevelItemDescriptor;
import hudson.security.ACL;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import jenkins.model.DirectlyModifiableTopLevelItemGroup;
import jenkins.model.Jenkins;
import org.htmlunit.Page;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.SleepBuilder;

public class Security2180Test {
    private static final String BUILD_CONTENT = "Started by user";
    private static final String JOB_CONTENT = "Full project name: folder/job";
    private static final Map<Permission, Set<String>> ANONYMOUS_CAN_ITEM_READ =
            Collections.singletonMap(Item.READ, Collections.singleton("anonymous"));

    @Rule
    public JenkinsRule j = new JenkinsRule();

    /**
     * Helper method that creates a nested folder structure: Each parameter but the last creates a folder, the last one
     * creates a freestyle job. Every non-null argument will be added as that item's property.
     * For example, to create just a job on the top level, pass a single argument, non-null if you want a job property.
     * For nulls will create a nested folder structure like folder1/folder2/folder3/item4 and none of them will have properties.
     * @param containers the {@link AuthorizationContainer}s to set for the corresponding nested folder or job.
     * @return The job inside the innermost folder, if any
     * @throws Exception when anything goes wrong
     */
    private FreeStyleProject prepareNestedProject(AuthorizationContainer... containers) throws Exception {
        int nestingLevel = containers.length;

        DirectlyModifiableTopLevelItemGroup parent = j.jenkins;

        TopLevelItem job = null;

        for (int i = 0; i < nestingLevel; i++) {
            final AuthorizationContainer container = containers[i];
            if (i == nestingLevel - 1) {
                // Create a job at the nested-most level
                final TopLevelItem project = parent.createProject(
                        TopLevelItemDescriptor.all().get(FreeStyleProject.DescriptorImpl.class), "item" + i, false);
                final FreeStyleProject freestyleProject = (FreeStyleProject) project;
                freestyleProject.getBuildersList().add(new SleepBuilder(100000));
                if (container != null) {
                    freestyleProject.addProperty((AuthorizationMatrixProperty) container);
                }
                freestyleProject.save();
                job = project;
            } else {
                // Create folder
                final TopLevelItem folder = parent.createProject(
                        TopLevelItemDescriptor.all().get(Folder.DescriptorImpl.class), "folder" + i, false);
                if (container != null) {
                    ((Folder) folder)
                            .addProperty((com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty)
                                    container);
                }
                folder.save();
                parent = (Folder) folder;
            }
        }

        return (FreeStyleProject) job;
    }

    /**
     * This triggers builds, so should only be called once. A single test may call this multiple times, each with a
     * different job, but care needs to be taken to ensure there are enough executors to schedule a build.
     */
    // We can save a lot of time by only asserting permission checks, not full WebClient page content, but for now keep
    // it in just in case.
    private void assertJobVisibility(FreeStyleProject job, boolean visibleWithFix, boolean visibleWithEscapeHatch)
            throws Exception {
        final String jobUrl = job.getUrl();
        // TODO robustness: check queue contents / executor status before scheduling
        job.scheduleBuild2(0, new Cause.UserIdCause("admin")).waitForStart(); // schedule one build now
        job.scheduleBuild2(0, new Cause.UserIdCause("admin")); // schedule an additional queue item
        Assert.assertEquals(1, Jenkins.get().getQueue().getItems().length); // expect there to be one queue item

        final JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false);

        { // UI
            final HtmlPage htmlPage = webClient.goTo("");
            final String contentAsString = htmlPage.getWebResponse().getContentAsString();
            if (visibleWithFix) {
                assertTrue(job.hasPermission2(Jenkins.ANONYMOUS2, Item.READ));
                assertTrue(job.hasPermission2(ACL.SYSTEM2, Item.READ));
                assertThat(contentAsString, containsString(jobUrl));
            } else {
                assertFalse(job.hasPermission2(Jenkins.ANONYMOUS2, Item.READ));
                assertTrue(job.hasPermission2(ACL.SYSTEM2, Item.READ));
                assertThat(contentAsString, not(containsString(jobUrl)));
            }
        }
        // TODO check API?

        final String propertyName =
                hudson.security.AuthorizationMatrixProperty.class.getName() + ".checkParentPermissions";
        try {
            System.setProperty(propertyName, "false");
            { // UI
                final HtmlPage htmlPage = webClient.goTo("");
                final String contentAsString = htmlPage.getWebResponse().getContentAsString();
                if (visibleWithEscapeHatch) {
                    assertTrue(job.hasPermission2(Jenkins.ANONYMOUS2, Item.READ));
                    assertTrue(job.hasPermission2(ACL.SYSTEM2, Item.READ));
                    assertThat(contentAsString, containsString(jobUrl));
                } else {
                    assertFalse(job.hasPermission2(Jenkins.ANONYMOUS2, Item.READ));
                    assertTrue(job.hasPermission2(ACL.SYSTEM2, Item.READ));
                    assertThat(contentAsString, not(containsString(jobUrl)));
                }
            }
        } finally {
            System.clearProperty(propertyName);
        }
    }

    private void prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Permission... extraPermissions) {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        final ProjectMatrixAuthorizationStrategy strategy = new ProjectMatrixAuthorizationStrategy();
        strategy.add(Jenkins.READ, "anonymous");
        strategy.add(Jenkins.ADMINISTER, "admin");
        for (Permission permission : extraPermissions) {
            strategy.add(permission, "anonymous");
        }
        j.jenkins.setAuthorizationStrategy(strategy);
    }

    private FreeStyleProject createFreeStyleProjectWithReadPermissionForAnonymousInFolder(Folder folder)
            throws java.io.IOException {
        FreeStyleProject job = folder.createProject(FreeStyleProject.class, "job");
        job.getBuildersList().add(new SleepBuilder(100000));
        job.addProperty(new AuthorizationMatrixProperty(
                Collections.singletonMap(Item.READ, Collections.singleton("anonymous"))));
        job.save();
        return job;
    }

    private com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty
            createFolderPropertyForAnonymousItemRead() {
        return createFolderProperty(Security2180Test.ANONYMOUS_CAN_ITEM_READ, new InheritParentStrategy());
    }

    private com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty createFolderProperty(
            Map<Permission, Set<String>> permissionSetMap, InheritanceStrategy inheritanceStrategy) {
        com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty property =
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(permissionSetMap);
        if (inheritanceStrategy != null) {
            property.setInheritanceStrategy(inheritanceStrategy);
        }
        return property;
    }

    private AuthorizationMatrixProperty createJobPropertyForAnonymousItemRead() {
        return createJobProperty(Security2180Test.ANONYMOUS_CAN_ITEM_READ, new InheritParentStrategy());
    }

    private AuthorizationMatrixProperty createJobProperty(
            Map<Permission, Set<String>> permissionSetMap, InheritanceStrategy inheritanceStrategy) {
        AuthorizationMatrixProperty property = new AuthorizationMatrixProperty(permissionSetMap);
        if (inheritanceStrategy != null) {
            property.setInheritanceStrategy(inheritanceStrategy);
        }
        return property;
    }

    @Test
    public void testQueuePath() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(null, new AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ));

        job.scheduleBuild2(1000, new Cause.UserIdCause("admin"));
        Assert.assertEquals(1, Jenkins.get().getQueue().getItems().length);

        final JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        final HtmlPage htmlPage = webClient.goTo("queue/items/0/task/");
        final String contentAsString = htmlPage.getWebResponse().getContentAsString();
        assertThat(contentAsString, not(containsString(JOB_CONTENT))); // Fails while unfixed
    }

    @Test
    public void testQueueContent() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(null, new AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ));

        job.scheduleBuild2(1000, new Cause.UserIdCause("admin"));
        Assert.assertEquals(1, Jenkins.get().getQueue().getItems().length);

        final JenkinsRule.WebClient webClient = j.createWebClient();
        final Page page = webClient.goTo("queue/api/xml/", "application/xml");
        final String xml = page.getWebResponse().getContentAsString();
        assertThat(xml, not(containsString(job.getUrl()))); // Fails while unfixed
    }

    @Test
    public void testExecutorsPath() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(null, new AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ));

        final FreeStyleBuild build =
                job.scheduleBuild2(0, new Cause.UserIdCause("admin")).waitForStart();
        final Executor executor = build.getExecutor();
        assertNotNull("null executor", executor);
        final int number = executor.getNumber();

        final JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false);
        final HtmlPage htmlPage = webClient.goTo("computer/(master)/executors/" + number + "/currentExecutable/");
        final String contentAsString = htmlPage.getWebResponse().getContentAsString();
        assertThat(contentAsString, not(containsString(BUILD_CONTENT))); // Fails while unfixed
    }

    @Test
    public void testExecutorsContent() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        Folder folder = j.jenkins.createProject(Folder.class, "folder");
        FreeStyleProject job = createFreeStyleProjectWithReadPermissionForAnonymousInFolder(folder);

        job.scheduleBuild2(0, new Cause.UserIdCause("admin")).waitForStart();

        final JenkinsRule.WebClient webClient = j.createWebClient();
        final Page page = webClient.goTo("computer/(master)/api/xml?depth=1", "application/xml");
        final String xml = page.getWebResponse().getContentAsString();
        assertThat(xml, not(containsString("job/folder/job/job"))); // Fails while unfixed
    }

    @Test
    public void testWidgets() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(null, createJobPropertyForAnonymousItemRead());

        job.scheduleBuild2(0, new Cause.UserIdCause("admin")).waitForStart(); // schedule one build now
        job.scheduleBuild2(0, new Cause.UserIdCause("admin")); // schedule an additional queue item
        Assert.assertEquals(1, Jenkins.get().getQueue().getItems().length); // expect there to be one queue item

        final JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false);

        final HtmlPage htmlPage = webClient.goTo("");
        final String contentAsString = htmlPage.getWebResponse().getContentAsString();
        assertThat(contentAsString, not(containsString("job/folder/job/job"))); // Fails while unfixed
    }

    @Test
    public void testTwoNestedFolderWithSecondGrantingAccess() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(
                null,
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ),
                new AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ));
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testThreeNestedFolderWithSecondGrantingAccess() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(
                null, // folder does not allow Item/Read for anon
                new com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty(
                        ANONYMOUS_CAN_ITEM_READ), // folder2 allows Item/Read for anon but should not matter
                null, // folder3 inherits from parent
                new AuthorizationMatrixProperty(ANONYMOUS_CAN_ITEM_READ));
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testGlobalItemReadBlockedByNonInheritingStrategyOnJob() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job =
                prepareNestedProject(null, createJobProperty(Collections.emptyMap(), new NonInheritingStrategy()));
        assertJobVisibility(job, false, false);
    }

    @Test
    public void testGlobalItemReadBlockedByNonInheritingStrategyOnMiddleFolder() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                null,
                createFolderProperty(Collections.emptyMap(), new NonInheritingStrategy()),
                createFolderPropertyForAnonymousItemRead(),
                createJobPropertyForAnonymousItemRead());
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testInheritGlobalMiddleFolderInheritParentInnerFolder() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        // Global( Item/Read ) -> folder (no prop) -> folder2 (prop inherits global) -> folder3 (prop inherits parent,
        // grants Read) -> job (grants Read)
        FreeStyleProject job = prepareNestedProject(
                null,
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createFolderPropertyForAnonymousItemRead(),
                createJobPropertyForAnonymousItemRead());
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testNonInheritingOuterFolderBlocksInheritGlobalInnerFolder() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        // Global( Item/Read ) -> folder (do not inherit) -> folder2 (prop inherits global) -> folder3 (prop inherits
        // parent, grants Read) -> job (grants Read)
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new NonInheritingStrategy()),
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createFolderPropertyForAnonymousItemRead(),
                createJobPropertyForAnonymousItemRead());
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testInheritGlobalInFolderInheritParentAndExplicitGrantInItem() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(ANONYMOUS_CAN_ITEM_READ, new InheritParentStrategy()));
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testInheritGlobalInFolderInheritParentWithoutExplicitGrantInItem_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testExplicitNonInheritingThenInheritGlobalReadThenParent_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(ANONYMOUS_CAN_ITEM_READ, new NonInheritingStrategy()),
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testNonInheritingThenInheritGlobalReadThenParent_not_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new NonInheritingStrategy()),
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testExplicitNonInheritingThenInheritGlobalNonReadThenParent_not_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(ANONYMOUS_CAN_ITEM_READ, new NonInheritingStrategy()),
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertJobVisibility(job, false, false);
    }

    @Test
    public void testExplicitNonInheritingThenInheritGlobalReadThenNonInheriting_not_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(ANONYMOUS_CAN_ITEM_READ, new NonInheritingStrategy()),
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new NonInheritingStrategy()));
        assertJobVisibility(job, false, false);
    }

    @Test
    public void testInheritGlobalInFolderInheritParentWithoutExplicitGrantInItem2_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritParentStrategy()));
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testInheritGlobalInFolderAndItem_visible() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous(Item.READ);
        FreeStyleProject job = prepareNestedProject(
                createFolderProperty(Collections.emptyMap(), new InheritGlobalStrategy()),
                createJobProperty(Collections.emptyMap(), new InheritGlobalStrategy()));
        assertJobVisibility(job, true, true);
    }

    @Test
    public void testNonInheritingItemWithExplicitGrantInsideNonGrantingFolder() throws Exception {
        prepareJenkinsDefaultSetupWithOverallReadForAnonymous();

        FreeStyleProject job =
                prepareNestedProject(null, createJobProperty(ANONYMOUS_CAN_ITEM_READ, new NonInheritingStrategy()));
        assertJobVisibility(job, false, true);
    }

    @Test
    public void testEscapeHatch() throws Exception {
        final String propertyName =
                hudson.security.AuthorizationMatrixProperty.class.getName() + ".checkParentPermissions";
        try {
            System.setProperty(propertyName, "false");

            prepareJenkinsDefaultSetupWithOverallReadForAnonymous();
            Folder folder = j.jenkins.createProject(Folder.class, "folder");
            FreeStyleProject job = createFreeStyleProjectWithReadPermissionForAnonymousInFolder(folder);

            job.scheduleBuild2(1000, new Cause.UserIdCause("admin"));
            Assert.assertEquals(1, Jenkins.get().getQueue().getItems().length);

            final JenkinsRule.WebClient webClient = j.createWebClient().withThrowExceptionOnFailingStatusCode(false);

            { // queue related assertions
                final HtmlPage htmlPage = webClient.goTo("queue/items/0/task/");
                final String contentAsString = htmlPage.getWebResponse().getContentAsString();
                assertThat(contentAsString, containsString(JOB_CONTENT)); // Fails while unfixed

                final Page page = webClient.goTo("queue/api/xml/", "application/xml");
                final String xml = page.getWebResponse().getContentAsString();
                assertThat(xml, containsString("job/folder/job/job")); // Fails while unfixed
            }

            final FreeStyleBuild build =
                    job.scheduleBuild2(0, new Cause.UserIdCause("admin")).waitForStart();
            final Executor executor = build.getExecutor();
            assertNotNull("null executor", executor);
            final int number = executor.getNumber();
            Assert.assertEquals(0, Jenkins.get().getQueue().getItems().length); // collapsed queue items

            { // executor related assertions
                final HtmlPage htmlPage =
                        webClient.goTo("computer/(master)/executors/" + number + "/currentExecutable/");
                final String contentAsString = htmlPage.getWebResponse().getContentAsString();
                assertThat(contentAsString, containsString(BUILD_CONTENT)); // Fails while unfixed

                final Page page = webClient.goTo("computer/(master)/api/xml?depth=1", "application/xml");
                final String xml = page.getWebResponse().getContentAsString();
                assertThat(xml, containsString("job/folder/job/job")); // Fails while unfixed
            }

            { // widget related assertions
                final HtmlPage htmlPage = webClient.goTo("");
                final String contentAsString = htmlPage.getWebResponse().getContentAsString();
                assertThat(contentAsString, containsString("job/folder/job/job")); // Fails while unfixed
            }

        } finally {
            System.clearProperty(propertyName);
        }
    }
}
