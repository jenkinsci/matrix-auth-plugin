/*
 * The MIT License
 *
 * Copyright (c) 2021 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.matrixauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.XmlFile;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.AdministrativeMonitor;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.Node;
import hudson.model.Saveable;
import hudson.model.listeners.ItemListener;
import hudson.model.listeners.SaveableListener;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import jenkins.model.NodeListener;
import jenkins.model.Nodes;
import jenkins.util.SystemProperties;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Warn when any configuration contains ambiguous permission assignments.
 */
@Extension
@Restricted(NoExternalUse.class)
public class AmbiguityMonitor extends AdministrativeMonitor {
    public static final Logger LOGGER = Logger.getLogger(AmbiguityMonitor.class.getName());

    public List<Contributor> getContributors() {
        return ExtensionList.lookup(Contributor.class);
    }

    @Override
    public String getDisplayName() {
        return Messages.AmbiguityMonitor_DisplayName();
    }

    @Override
    public boolean isSecurity() {
        return true;
    }

    @Override
    public boolean isActivated() {
        if (DISABLE) {
            return false;
        }

        List<Contributor> contributors = getContributors();
        for (Contributor contributor : contributors) {
            if (contributor.hasAmbiguousEntries()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Implementations must provide a {@code entries.jelly} file to display their ambiguous items as top-level {@code <li>} items (it will be displayed in a {@code <ul>}.
     *
     */
    public interface Contributor extends ExtensionPoint {
        /**
         * Whether there are ambiguous items present.
         */
        boolean hasAmbiguousEntries();
    }

    // to have it first in the message
    @Extension(ordinal = 10)
    public static class GlobalConfigurationContributor implements Contributor {
        @Override
        public boolean hasAmbiguousEntries() {
            AuthorizationStrategy authorizationStrategy = Jenkins.get().getAuthorizationStrategy();
            if (authorizationStrategy instanceof GlobalMatrixAuthorizationStrategy) {
                return AmbiguityMonitor.hasAmbiguousEntries((GlobalMatrixAuthorizationStrategy) authorizationStrategy);
            }
            return false;
        }
    }

    @Extension
    public static class NodeContributor implements Contributor {
        public final Map<String, Boolean> activeNodes = Collections.synchronizedMap(new TreeMap<>());

        @Override
        public boolean hasAmbiguousEntries() {
            return Jenkins.get().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy
                    && activeNodes.values().stream().anyMatch(v -> v);
        }

        public static void record(Node node) {
            if (!DISABLE) {
                boolean value = AmbiguityMonitor.hasAmbiguousEntries(
                        node.getNodeProperty(AuthorizationMatrixNodeProperty.class));
                LOGGER.log(Level.FINE, () -> "Recording node " + node + " as having ambiguous entries? " + value);
                ExtensionList.lookupSingleton(NodeContributor.class).activeNodes.put(node.getNodeName(), value);
            }
        }

        public static void remove(String nodeName) {
            if (!DISABLE) {
                LOGGER.log(Level.FINE, () -> "Removing node " + nodeName);
                ExtensionList.lookupSingleton(NodeContributor.class).activeNodes.remove(nodeName);
            }
        }

        @Extension
        public static class NodeListenerImpl extends NodeListener {
            @Override
            protected void onCreated(@NonNull Node node) {
                record(node);
            }

            @Override
            protected void onDeleted(@NonNull Node node) {
                if (!DISABLE) {
                    remove(node.getNodeName());
                }
            }
        }
    }

    @Extension
    public static class JobContributor implements Contributor {
        public final Map<String, Boolean> activeJobs = Collections.synchronizedMap(new TreeMap<>());

        @Override
        public boolean hasAmbiguousEntries() {
            return Jenkins.get().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy
                    && activeJobs.values().stream().anyMatch(v -> v);
        }

        public static void update(Job<?, ?> job) {
            if (!DISABLE) {
                boolean value =
                        AmbiguityMonitor.hasAmbiguousEntries(job.getProperty(AuthorizationMatrixProperty.class));
                LOGGER.log(Level.FINE, () -> "Recording job " + job + " as having ambiguous entries? " + value);
                ExtensionList.lookupSingleton(JobContributor.class).activeJobs.put(job.getFullName(), value);
            }
        }

        public static void remove(String jobName) {
            if (!DISABLE) {
                LOGGER.log(Level.FINE, () -> "Removing job " + jobName);
                ExtensionList.lookupSingleton(JobContributor.class).activeJobs.remove(jobName);
            }
        }

        // for Jelly
        public List<Item> getEntries() {
            return activeJobs.entrySet().stream()
                    .filter(Map.Entry::getValue)
                    .map(Map.Entry::getKey)
                    .map(v -> Jenkins.get().getItemByFullName(v))
                    .filter(Objects::nonNull)
                    .sorted(Comparator.comparing(Item::getFullDisplayName, String.CASE_INSENSITIVE_ORDER))
                    .collect(Collectors.toList());
        }

        @Extension
        public static class JobListenerImpl extends ItemListener {
            @Override
            public void onCreated(Item item) {
                if (item instanceof Job) {
                    update((Job<?, ?>) item);
                }
            }

            @Override
            public void onLocationChanged(Item item, String oldFullName, String newFullName) {
                if (AmbiguityMonitor.isGatheringData()) {
                    if (item instanceof Job) {
                        remove(oldFullName);
                        update((Job<?, ?>) item);
                    }
                }
            }

            @Override
            public void onDeleted(Item item) {
                if (!DISABLE) {
                    if (item instanceof Job) {
                        // This needs special handling because strictly speaking, the configuration isn't updated to not
                        // be ambiguous
                        remove(item.getFullName());
                    }
                }
            }
        }
    }

    public static boolean hasAmbiguousEntries(final AuthorizationContainer container) {
        if (container == null) {
            return false;
        }
        return container.getAllPermissionEntries().stream().anyMatch(e -> e.getType() == AuthorizationType.EITHER);
    }

    @Extension
    public static class NodeAndJobSaveableListenerImpl extends SaveableListener {
        @Override
        public void onChange(final Saveable o, final XmlFile file) {
            if (!AmbiguityMonitor.isGatheringData()) {
                return; // The below is a bit much when we're not doing anything in the end, so get out early
            }
            try {
                if (o instanceof Nodes) {
                    LOGGER.log(Level.FINEST, () -> "Recording update to Saveable " + o + " stored in " + file);

                    // Cf. Nodes#persistNode, hacky but probably the best we can do
                    final String nodeName = file.getFile().getParentFile().getName();
                    // Nodes is @Restricted but the Saveable we inform listeners about, so go through Jenkins#getNode
                    // instead
                    final Node node = Jenkins.get().getNode(nodeName);
                    LOGGER.log(
                            Level.FINER,
                            () -> "Determined node name " + nodeName + " from file " + file + " and found node "
                                    + node);
                    if (node != null) {
                        NodeContributor.record(node);
                    }
                }
                if (o instanceof Job) {
                    LOGGER.log(Level.FINEST, () -> "Recording update to Saveable " + o + " stored in " + file);

                    JobContributor.update((Job<?, ?>) o);
                }
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, ex, () -> "Exception while updating status for " + o);
            }
        }
    }

    /**
     * For folder and job properties, we hook into their #setOwner method.
     * Node properties have no such method, so we need to scan them after startup.
     */
    @Initializer(after = InitMilestone.SYSTEM_CONFIG_ADAPTED)
    public static void recordAgents() {
        LOGGER.log(Level.FINE, () -> "Recording nodes");
        Jenkins.get().getNodes().forEach(NodeContributor::record);
    }

    private static /* non-final for Groovy */ boolean DISABLE =
            SystemProperties.getBoolean(AmbiguityMonitor.class.getName() + ".DISABLE");

    // "isGatheringData" as "isEnabled" is already defined at the parent level
    public static boolean isGatheringData() {
        return !DISABLE;
    }
}
