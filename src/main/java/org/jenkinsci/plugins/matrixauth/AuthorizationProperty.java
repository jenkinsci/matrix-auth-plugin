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

import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public interface AuthorizationProperty extends AuthorizationContainer {

    void setInheritanceStrategy(InheritanceStrategy inheritanceStrategy);

    InheritanceStrategy getInheritanceStrategy();

    /**
     * Sets the flag to block inheritance.
     *
     * Since the introduction of inheritance strategies, set the inheritance
     * strategy roughly matching the previous behavior, i.e. {@code false} will
     * set the {@link NonInheritingStrategy}, {@code true} will set the
     * {@link InheritGlobalStrategy}.
     *
     * Note that for items nested inside folders, this will change behavior significantly.
     *
     * @since 2.0
     * @deprecated Use {@link InheritanceStrategy} instead.
     */
    @Deprecated
    default void setBlocksInheritance(boolean blocksInheritance) {
        if (blocksInheritance) {
            setInheritanceStrategy(new NonInheritingStrategy());
        } else {
            setInheritanceStrategy(new InheritGlobalStrategy());
        }
    }

    /**
     * Returns true if the authorization matrix is configured to block
     * inheritance from the parent.
     *
     * Since the introduction of inheritance strategies, returns {@code true}
     * if and only if the selected inheritance strategy is {@link NonInheritingStrategy}.
     *
     * @since 2.0
     * @deprecated Use {@link #getInheritanceStrategy()} instead.
     */
    @Deprecated
    default boolean isBlocksInheritance() {
        return getInheritanceStrategy() instanceof NonInheritingStrategy;
    }
}
