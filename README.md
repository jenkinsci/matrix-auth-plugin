# Matrix Authorization Strategy Plugin

Implement fine-grained access control in Jenkins with this plugin.

For a basic introduction, see [the section on Matrix Authorization in the Jenkins handbook](https://jenkins.io/doc/book/managing/security/#authorization).

## Changelog

See [GitHub Releases](https://github.com/jenkinsci/matrix-auth-plugin/releases) (2.6.5 and newer only) or [CHANGELOG](CHANGELOG.md) (before 2.6.5).

## Use Cases

Matrix Authorization allows configuring the lowest level permissions, such as starting new builds, configuring items, or deleting them, individually.

### Project-based configuration

Project-based matrix authorization allows configuring permissions for each item or agent independently.
Permission applying to such items or agents that are granted in the global configuration apply to all of them, unless they don't inherit global permissions (see below).

### Permission inheritance

With project-based matrix authorization, permissions are by inherited from the global configuration and any parent entities (e.g. the folder a job is in) by default.
This can be changed.
Depending on the entity being configured, all or a subset of the following _inheritance strategies_ are available:

* Inherit permissions:
  This is the default behavior.
  Permissions explicitly granted on individual items or agents will only add to permissions defined globally or in any parent items.
* Inherit global configuration only:
  This will only inherit permissions granted globally, but not those granted on parent folders.
  This way, jobs in folders can control access independently from their parent folder.
* Do not inherit permissions:
  The most restrictive inheritance configuration.
  Only permissions defined explicitly on this agent or item will be granted.
  The only exception is Overall/Administer:
  It is not possible to remove access to an agent or item from Jenkins administrators.

### Configuration as Code and Job DSL support

Matrix Authorization Strategy Plugin has full support for use in Configuration as Code and Job DSL.

For an example combining the two, see [this `configuration-as-code.yml` test resource](https://github.com/jenkinsci/matrix-auth-plugin/blob/master/src/test/resources/org/jenkinsci/plugins/matrixauth/integrations/casc/configuration-as-code-v3.yml).


## Caveats

When using project-based matrix authorization, users granted permission to configure items or agents will be able to grant themselves all other permissions on the item or agent.
These would be inherited unless specifically disabled.

Beyond the above, administrators implementing fine-grained permissions control need to be aware of interactions between permissions, and certain overlap between them.
Some examples:

* A user not granted read access to Jenkins in general will not be able to use most of the other permissions they've been granted -- likely none of them.
* A user not granted read access to a job will not be able to start new builds, delete the job, configure the job, etc.
* When using global matrix authorization, users granted permission to configure jobs but not start them will still be able to configure the job to be periodically executed.
* Some permissions imply others.
  Most notably, Overall/Administer implies (almost) all other permissions, but other implications exist:
  For example, Job/Read implies Job/Discover.
  Descriptions for permissions will note when a permission is either implied by a permission other than Overall/Administer, or when it is not implied by any other permission.
