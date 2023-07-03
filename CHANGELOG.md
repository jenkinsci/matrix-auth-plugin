# Changelog

Release notes for Version 3.0 and newer are published in [GitHub Releases](https://github.com/jenkinsci/matrix-auth-plugin/releases) only. 

## Version 2.6.11 (2021-12-08)

* [JENKINS-67311](https://issues.jenkins.io/browse/JENKINS-67311): Fix help button for table ([#108](https://github.com/jenkinsci/matrix-auth-plugin/pull/108))

## Version 2.6.9 (2021-12-03)

* [JENKINS-67210](https://issues.jenkins.io/browse/JENKINS-67210): Fix broken link to global security configuration from help ([#106](https://github.com/jenkinsci/matrix-auth-plugin/pull/106))
* [JENKINS-66964](https://issues.jenkins.io/browse/JENKINS-66964): Fix button tooltips in configuration matrix ([#107](https://github.com/jenkinsci/matrix-auth-plugin/pull/107))

## Version 2.6.8 (2021-07-21)

* [JENKINS-66170](https://issues.jenkins.io/browse/JENKINS-66170): Apply table style when viewing in read-only mode (Extended Read permission).
  This fixes a regression in version 2.6.7.

## Version 2.6.7 (2021-05-12)

* Internal: Moved JavaScript to resource files ([#102](https://github.com/jenkinsci/matrix-auth-plugin/pull/102))
* Internal: Migrate from RestartableJenkinsRule to JenkinsSessionRule ([#101](https://github.com/jenkinsci/matrix-auth-plugin/pull/101))

## Version 2.6.6 (2021-03-18)

* [SECURITY-2180](https://www.jenkins.io/security/advisory/2021-03-18/#SECURITY-2180): Ensure Item/Read is only granted it all ancestors grant it as well.

## Version 2.6.5 (2021-01-21)

* [JENKINS-64661](https://issues.jenkins.io/browse/JENKINS-64661): Do not break `properties` in the global Pipeline snippet generator.

## Version 2.6.4 (2020-10-26)

* Compatibility with [JEP-228](https://github.com/jenkinsci/jep/blob/master/jep/228/README.adoc) in Jenkins 2.266 and newer.

## Version 2.6.3 (2020-09-15)

* [JENKINS-56109](https://issues.jenkins.io/browse/JENKINS-56109): Make the plugin compatible with new form layout in Jenkins 2.264 and newer.
* Open links from job, folder, and agent configurations to the Global Security Configuration in a new window.
* Internal: Parent POM update, make test assertions compatible with [JEP-295](https://github.com/jenkinsci/jep/blob/master/jep/295/README.adoc)

## Version 2.6.2 (2020-07-15)

* Fix [SECURITY-1909](https://www.jenkins.io/security/advisory/2020-07-15/#SECURITY-1909)

## Version 2.6.1 (2020-05-08)

* [JENKINS-62202](https://issues.jenkins.io/browse/JENKINS-62202):
  Fix regression introduced in 2.6 that disabled per-job/folder/agent configuration UI for users without Overall/Administer.

## Version 2.6 (2020-04-30)

* Increase minimum required Jenkins version to 2.222.1.
* Remove support for setting "dangerous permissions" as they are deprecated from Jenkins 2.222.x anyway.
  ([Jenkins LTS upgrade guide](https://www.jenkins.io/doc/upgrade-guide/2.222/#dangerous-permissions-deprecation),
  [SECURITY-410 in the 2017-04-10 security advisory](https://www.jenkins.io/security/advisory/2017-04-10/#matrix-authorization-strategy-plugin-allowed-configuring-dangerous-permissions))
* Add support for Overall/System Read permission (global configuration is rendered with disabled checkboxes).
* [JENKINS-36625](https://issues.jenkins.io/browse/JENKINS-36625):
  Allow wrapping long user and group names to limit width of the configuration table.
* Internal: Parent POM update, update test dependencies (Pipeline: Groovy Plugin, JCasC test harness).

## Version 2.5.1 (2020-07-15)

* Fix [SECURITY-1909](https://www.jenkins.io/security/advisory/2020-07-15/#SECURITY-1909) (backport)

## Version 2.5 (2019-10-14)

* [JENKINS-58703](https://issues.jenkins.io/browse/JENKINS-58703):
  Creating items through the remote API (`createItem`) could result in duplicate XML elements.
* [JENKINS-54568](https://issues.jenkins.io/browse/JENKINS-54568):
  Make `authorizationMatrix` work in declarative snippet generator.
* [JENKINS-46914](https://issues.jenkins.io/browse/JENKINS-46914):
  Better indicate implied permissions in the checkbox grid by disabling implied permission checkboxes.
* [JENKINS-47885](https://issues.jenkins.io/browse/JENKINS-47885):
  Make node property work in Kubernetes (and old versions of Docker) Plugin templates.
* Move plugin documentation from the Jenkins wiki to GitHub.

## Version 2.4.2 (2019-05-02)

* [JENKINS-57313](https://issues.jenkins.io/browse/JENKINS-57313): Fix a bug introduced in 2.4 that could result in exception error messages shown on the configuration page when permissions are assigned to valid user accounts that have never logged in to Jenkins.

## Version 2.4.1 (2019-04-27)

* Fix a bug introduced in 2.4 that could prevent agent configurations from being loaded

## Version 2.4 (2019-04-24)

* Increase core dependency from 2.60.1 to 2.138.3
* Configuration as Code compatibility: Integrate configurators for global and agent permissions.
* Job DSL compatibility: Add support for configuring folder permission inheritance using `authorizationMatrix` symbol
* Job DSL compatibility: Allow setting permissions using user-friendly names like _Overall/Read_
* Fix a minor UI glitch on job configuration pages

## Version 2.3 (2018-07-10)

* [JENKINS-52167](https://issues.jenkins.io/browse/JENKINS-52167): Rotate column headers in Google Chrome
* [JENKINS-47424](https://issues.jenkins.io/browse/JENKINS-47424): Don't show 'Implied by' note for the Overall/Administer permission
* [JENKINS-28668](https://issues.jenkins.io/browse/JENKINS-28668): Use a modal dialog to add users/groups to the list to prevent accidental form submissions

## Version 2.2 (2017-11-12)

* [JENKINS-47885](https://issues.jenkins.io/browse/JENKINS-47885): Work around a JavaScript error in the Configure Jenkins form when the Kubernetes plugin is installed.
* Improve performance of permission checks for internal SYSTEM user.

## Version 2.1.1 (2017-11-02)

* Do not show a warning on Jenkins startup when the Folders Plugin is not installed.

## Version 2.1 (2017-10-12)

* [JENKINS-47412](https://issues.jenkins.io/browse/JENKINS-47412): Fix a bug introduced in 2.0 that prevented creation of new agents via the UI.

## Version 2.0 (2017-10-09)

**Note for users of version 2.0-beta-3: There have been no changes since that release.**

### Important upgrade notes

* This release requires **Jenkins 2.60.1** or newer as it makes extensive use of Java 8 features (and there's currently no way to declare a minimum needed Java version other than to depend on a core that requires that Java release).
* This release uses a **new on-disk format** for permissions inheritance options. Existing options will be retained when upgrading, but **downgrading to older versions may result in failures to load job or folder permission data, or different (typically additional) permissions being granted after the downgrade.**
* Support for loading permissions last saved before Jenkins 1.300 (April 2009) has been dropped from this release.

### Notable changes since 1.7

* **Flexible permission inheritance options**
    * This replaces the 'blocks inheritance' feature implemented in version 1.2\. **The on-disk storage format has changed to support this.**
    * Ensure that even "blocking inheritance" does not block administrator access. ([JENKINS-24878](https://issues.jenkins.io/browse/JENKINS-24878))
    * Improve wording of inheritance options and include inline explanation about the effects. ([JENKINS-39409](https://issues.jenkins.io/browse/JENKINS-39409))
* **Allow configuring per-agent permissions.** This allows e.g. restricting per-agent build permissions when using the Authorize Project plugin ([JENKINS-46654](https://issues.jenkins.io/browse/JENKINS-46654))
* **Prevent accidental lockouts and unexpected lack of permissions**  
    * Improvement: When submitting a global matrix auth configuration that does not specify an administrator (often happening in accidental/premature form submissions), give the submitting user Administer permission. Note that this could mean that the 'anonymous' may still have admin permission if the form is submitted as an anonymous user. ([JENKINS-46832](https://issues.jenkins.io/browse/JENKINS-46832) / [JENKINS-10871](https://issues.jenkins.io/browse/JENKINS-10871))
    * Bug: Ensure that users creating a new job, folder, or node have read and configure access when using the project-based matrix authorization strategy. ([JENKINS-5277](https://issues.jenkins.io/browse/JENKINS-5277))
    * Bug: Save the global security configuration after granting administer permission to the first user to sign up. ([JENKINS-20520](https://issues.jenkins.io/browse/JENKINS-20520))
    * Bug: Ensure 'empty' matrix permission configurations can be loaded in case this is needed (e.g. programmatically defined). The fix for [JENKINS-10871](https://issues.jenkins.io/browse/JENKINS-10871) will prevent this from happening accidentally. ([JENKINS-9774](https://issues.jenkins.io/browse/JENKINS-9774))
    * Bug: When using container-based authentication and project-based matrix authorization, permissions granted to groups in items inside folders only may not have been granted to members of those groups.
* **UX improvements for the matrix configuration table**  
    * Improvement: Indicate whether a permission is implied by another permission in the tool tip, and also indicate when a permission is not implied by Overall/Administer (which is unusual). ([JENKINS-32506](https://issues.jenkins.io/browse/JENKINS-32506))
    * Improvement: Show the full name of the user, if found, instead of the user ID. The user ID is available in the tool tip. ([JENKINS-14563](https://issues.jenkins.io/browse/JENKINS-14563))
    * Improvement: Always list the 'authenticated' group, list it and 'anonymous' first, and give both of them friendly localizable display names ([JENKINS-30495](https://issues.jenkins.io/browse/JENKINS-30495))
    * Improvement: Improve usability of large permission tables: Add tool tips for permission checkboxes indicating the user ID and permission involved, and add tool tips indicating affected user/group for the actions to the right of table rows. ([JENKINS-26824](https://issues.jenkins.io/browse/JENKINS-26824))
* **Add support for use in the `properties()` pipeline step. For usage example, see the snippet generator.** ([JENKINS-34616](https://issues.jenkins.io/browse/JENKINS-34616))
* Bug: Support case sensitivity for per-folder permissions as well, was missed in 1.7\. ([JENKINS-23805](https://issues.jenkins.io/browse/JENKINS-23805))
* Bug: Prevent `NullPointerException` getting logged when a matrix auth config form is viewed. ([JENKINS-46190](https://issues.jenkins.io/browse/JENKINS-46190))
* Use PNG icons with transparent background rather than GIF with white background.
* Major internal cleanup and code simplification
    * Drop support for data migration (Item.Read permission) from Jenkins 1.300 and earlier
    * Drop support for loading project-based matrix permissions last saved before September 2008

## Version 2.0-beta-3 (2017-09-20)

### Notable changes in this release

* New Feature: Add support for use in the `properties()` pipeline step. For usage example, see the snippet generator. ([JENKINS-34616](https://issues.jenkins.io/browse/JENKINS-34616))

## Version 2.0-beta-2 (2017-09-19)

### Notable changes in this release

* Fix regression in 2.0-beta-1 that broke compatibility with Role-based Authorization Strategy Plugin (role-strategy). ([JENKINS-46923](https://issues.jenkins.io/browse/JENKINS-46923))
* Fix regression in 2.0-beta-1 that made permission tool tips disappear in job, folder, and node property configuration forms.
* Fix regression in 2.0-beta-1 that showed permission group table cells in the config form for groups that did not apply to the current job, folder, or node property.
* Use PNG icons with transparent background rather than GIF with white background.
* Fix label of node property introduced in 2.0-beta-1.
* Show user IDs in tooltips for checkboxes and buttons in newly added rows.
* Internal refactoring to reduce code duplication.
* Restrict external use of some APIs newly introduced since 1.7.

## Version 2.0-beta-1 (2017-09-16)

### Notable changes in this release

* Most of the features and fixes that made it into version 2.0.

## Version 1.7 (Jun 28, 2017)

* [JENKINS-44665](https://issues.jenkins.io/browse/JENKINS-44665) Select All/None buttons rather than a button to invert.

* [JENKINS-23805](https://issues.jenkins.io/browse/JENKINS-23805) Support case sensitivity modes of the security realm.

## Version 1.6 (May 18, 2017)

* [JENKINS-29815](https://issues.jenkins.io/browse/JENKINS-29815) Add the same tick-box to disable inheritance of global permissions to Folders as already existed for Projects.

## Version 1.5 (Apr 10, 2017)

* [SECURITY-410](https://jenkins.io/security/advisory/2017-04-10/#matrix-authorization-strategy-plugin-allowed-configuring-dangerous-permissions): plugin allowed configuration of dangerous permissions. See advisory for details.

## Version 1.4 (May 24, 2016)

* Stack trace displayed on startup with Folders plugin disabled or missing.
* Better display of unrecognized usernames in configuration matrix.

## Version 1.3.2 (Feb 25, 2016)

* Stack trace displayed when attempting to configure authorization property on a folder.

## Version 1.3.1 (Feb 25, 2016)

* Moved forgotten resource from the Folders plugin. Also now forces the Icon Shim update.

## Version 1.3 (Feb 22, 2016)

* Inverted dependency so this plugin now depends on the [CloudBees Folders Plugin](https://plugins.jenkins.io/cloudbees-folder/).
  **If you accept this update, you must also update the [Icon Shim Plugin](https://plugins.jenkins.io/icon-shim/) (to 2.0.3 or later).**
* Extended diagnostic fix made in 1.1.
* Silently ignore unknown permissions instead of throwing an `IllegalArgumentException`.
* [JENKINS-29527](https://issues.jenkins.io/browse/JENKINS-29527) Fixed bug in inheritance blocking.
* [JENKINS-31860](https://issues.jenkins.io/browse/JENKINS-31860) `ClassCastException` when used with multibranch projects.

## Version 1.2 (Apr 19, 2014)

* Allow a job to not inherit from global ACL ([JENKINS-10593](https://issues.jenkins.io/browse/JENKINS-10593))

## Version 1.1 (Nov 11, 2013)

* Using an extension point in Jenkins 1.535.
* Better diagnosis for a form-related error.

## Version 1.0, 1.0.1, 1.0.2 (Oct 04, 2013)

* Split from Jenkins core.
