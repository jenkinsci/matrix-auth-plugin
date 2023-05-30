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

import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.ExtendedHierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public abstract class AbstractAuthorizationPropertyConverter<T extends AuthorizationProperty>
        extends AbstractAuthorizationContainerConverter<T> {
    public abstract boolean canConvert(Class type);

    public abstract T create();

    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        AuthorizationProperty authorizationProperty = (AuthorizationProperty) source;

        InheritanceStrategy strategy = authorizationProperty.getInheritanceStrategy();
        if (strategy != null) {
            writer.startNode("inheritanceStrategy");
            writer.addAttribute("class", strategy.getClass().getCanonicalName());
            writer.endNode();
        }

        super.marshal(source, writer, context);
    }

    @Override
    protected void unmarshalContainer(T container, HierarchicalStreamReader reader, UnmarshallingContext context) {
        String prop = ((ExtendedHierarchicalStreamReader) reader).peekNextChild();

        if (prop != null && prop.equals("useProjectSecurity")) {
            reader.moveDown();
            reader.getValue(); // we used to use this but not any more.
            reader.moveUp();
            prop = ((ExtendedHierarchicalStreamReader) reader).peekNextChild(); // We check the next field
        }
        if ("blocksInheritance".equals(prop)) {
            reader.moveDown();
            boolean blocksInheritance = "true".equals(reader.getValue());
            if (blocksInheritance) {
                container.setInheritanceStrategy(new NonInheritingStrategy());
            }
            reader.moveUp();
        }

        if ("inheritanceStrategy".equals(prop)) {
            reader.moveDown();
            String clazz = reader.getAttribute("class");
            try {
                container.setInheritanceStrategy(
                        (InheritanceStrategy) Class.forName(clazz).newInstance());
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to restore inheritance strategy", e);
            }
            reader.moveUp();
        }

        // let the super handle the permissions that are always towards the end
        super.unmarshalContainer(container, reader, context);
    }

    private static final Logger LOGGER = Logger.getLogger(AbstractAuthorizationPropertyConverter.class.getName());
}
