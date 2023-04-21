/*
 * The MIT License
 *
 * Copyright (c) 2004-2017 Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts, Daniel Beck
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

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.security.Permission;
import hudson.util.RobustReflectionConverter;
import java.util.Comparator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public abstract class AbstractAuthorizationContainerConverter<T extends AuthorizationContainer> implements Converter {
    public abstract boolean canConvert(Class type);

    public abstract T create();

    @SuppressWarnings("unchecked")
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        final Comparator<PermissionEntry> comparator = new AuthorizationContainer.PermissionEntryComparator();

        if (!canConvert(source.getClass())) {
            throw new IllegalArgumentException("cannot marshal object of type " + source.getClass());
        }
        T container = (T) source;

        // Output in alphabetical order for readability.
        SortedMap<Permission, Set<PermissionEntry>> sortedPermissions = new TreeMap<>(Permission.ID_COMPARATOR);
        sortedPermissions.putAll(container.getGrantedPermissionEntries());

        for (Map.Entry<Permission, Set<PermissionEntry>> e : sortedPermissions.entrySet()) {
            String p = e.getKey().getId();
            Set<PermissionEntry> entries = new TreeSet<>(comparator);
            entries.addAll(e.getValue());

            for (PermissionEntry entry : entries) {
                writer.startNode("permission");
                writer.setValue(entry.getType().toPrefix() + p + ':' + entry.getSid());
                writer.endNode();
            }
        }
    }

    protected void unmarshalContainer(
            T container, HierarchicalStreamReader reader, final UnmarshallingContext context) {
        while (reader.hasMoreChildren()) {
            reader.moveDown();
            try {
                container.add(reader.getValue());
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(AbstractAuthorizationContainerConverter.class.getName())
                        .log(Level.WARNING, "Skipping a non-existent permission", ex);
                RobustReflectionConverter.addErrorInContext(context, ex);
            }
            reader.moveUp();
        }
    }

    public Object unmarshal(HierarchicalStreamReader reader, final UnmarshallingContext context) {
        T container = create();
        unmarshalContainer(container, reader, context);

        return container;
    }
}
