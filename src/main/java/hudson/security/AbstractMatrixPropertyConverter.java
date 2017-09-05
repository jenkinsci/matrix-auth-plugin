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
package hudson.security;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.util.RobustReflectionConverter;

import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractMatrixPropertyConverter implements Converter {
    abstract public boolean canConvert(Class type);

    abstract public AuthorizationProperty createSubject();

    public void marshal(Object source, HierarchicalStreamWriter writer,
                        MarshallingContext context) {
        AuthorizationProperty authorizationProperty = (AuthorizationProperty) source;

        if (authorizationProperty.isBlocksInheritance()) {
            writer.startNode("blocksInheritance");
            writer.setValue("true");
            writer.endNode();
        }

        for (Map.Entry<Permission, Set<String>> e : authorizationProperty.getGrantedPermissions()
                .entrySet()) {
            String p = e.getKey().getId();
            for (String sid : e.getValue()) {
                writer.startNode("permission");
                writer.setValue(p + ':' + sid);
                writer.endNode();
            }
        }
    }

    public Object unmarshal(HierarchicalStreamReader reader,
                            final UnmarshallingContext context) {
        AuthorizationProperty authorizationProperty = createSubject();

        String prop = reader.peekNextChild();

        if (prop!=null && prop.equals("useProjectSecurity")) {
            reader.moveDown();
            reader.getValue(); // we used to use this but not any more.
            reader.moveUp();
            prop = reader.peekNextChild(); // We check the next field
        }
        if ("blocksInheritance".equals(prop)) {
            reader.moveDown();
            authorizationProperty.setBlocksInheritance("true".equals(reader.getValue()));
            reader.moveUp();
        }

        while (reader.hasMoreChildren()) {
            reader.moveDown();
            try {
                authorizationProperty.add(reader.getValue());
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(AuthorizationMatrixProperty.class.getName())
                        .log(Level.WARNING,"Skipping a non-existent permission",ex);
                RobustReflectionConverter.addErrorInContext(context, ex);
            }
            reader.moveUp();
        }

        return authorizationProperty;
    }
}
