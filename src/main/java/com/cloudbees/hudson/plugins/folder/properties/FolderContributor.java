/*
 * The MIT License
 *
 * Copyright (c) 2021, CloudBees, Inc.
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
package com.cloudbees.hudson.plugins.folder.properties;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.XmlFile;
import hudson.model.Item;
import hudson.model.Saveable;
import hudson.model.listeners.ItemListener;
import hudson.model.listeners.SaveableListener;
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
import org.jenkinsci.plugins.matrixauth.AmbiguityMonitor;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
@Extension(optional = true)
public class FolderContributor implements AmbiguityMonitor.Contributor {
    public static final Logger LOGGER = Logger.getLogger(FolderContributor.class.getName());

    public final Map<String, Boolean> activeFolders = Collections.synchronizedMap(new TreeMap<>());

    @Override
    public boolean hasAmbiguousEntries() {
        return Jenkins.get().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy
                && activeFolders.values().stream().anyMatch(v -> v);
    }

    public static void record(final AbstractFolder<?> folder) {
        if (AmbiguityMonitor.isGatheringData()) {
            final boolean value =
                    AmbiguityMonitor.hasAmbiguousEntries(folder.getProperties().get(AuthorizationMatrixProperty.class));
            LOGGER.log(Level.FINE, () -> "Recording folder " + folder + " as having ambiguous entries? " + value);
            ExtensionList.lookupSingleton(FolderContributor.class).activeFolders.put(folder.getFullName(), value);
        }
    }

    public static void remove(final String folderName) {
        if (AmbiguityMonitor.isGatheringData()) {
            LOGGER.log(Level.FINE, () -> "Removing folder " + folderName);
            ExtensionList.lookupSingleton(FolderContributor.class).activeFolders.remove(folderName);
        }
    }

    // for Jelly
    public List<Item> getEntries() {
        return activeFolders.entrySet().stream()
                .filter(Map.Entry::getValue)
                .map(Map.Entry::getKey)
                .map(v -> Jenkins.get().getItemByFullName(v))
                .filter(Objects::nonNull)
                .sorted(Comparator.comparing(Item::getFullDisplayName, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toList());
    }

    @Extension(optional = true)
    public static class FolderListenerImpl extends ItemListener implements OptionalMarker<AbstractFolder<?>> {
        @Override
        public void onCreated(Item item) {
            if (item instanceof AbstractFolder<?>) {
                record((AbstractFolder<?>) item);
            }
        }

        @Override
        public void onLocationChanged(Item item, String oldFullName, String newFullName) {
            if (AmbiguityMonitor.isGatheringData()) {
                if (item instanceof AbstractFolder<?>) {
                    remove(oldFullName);
                    record((AbstractFolder<?>) item);
                }
            }
        }

        @Override
        public void onDeleted(Item item) {
            if (AmbiguityMonitor.isGatheringData()) {
                if (item instanceof AbstractFolder<?>) {
                    AbstractFolder<?> folder = (AbstractFolder<?>) item;
                    // This needs special handling because strictly speaking, the configuration isn't updated to not be
                    // ambiguous
                    remove(folder.getFullName());
                }
            }
        }
    }

    @Extension(optional = true)
    public static class FolderSaveableListenerImpl extends SaveableListener implements OptionalMarker<Folder> {
        @Override
        public void onChange(final Saveable o, final XmlFile file) {
            try {
                if (o instanceof Folder) {
                    LOGGER.log(Level.FINEST, () -> "Recording update to Saveable " + o + " stored in " + file);
                    record((Folder) o);
                }
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, ex, () -> "Exception while updating status for " + o);
            }
        }
    }
}
