/*
 * The MIT License
 *
 * Copyright (c) 2018-2019 Matrix Authorization Strategy Plugin developers
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
package org.jenkinsci.plugins.matrixauth.integrations.casc;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.impl.attributes.DescribableAttribute;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import io.jenkins.plugins.casc.model.Mapping;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Extension(optional = true)
@Restricted(NoExternalUse.class)
public class AuthorizationMatrixNodePropertyConfigurator extends BaseConfigurator<AuthorizationMatrixNodeProperty> {

    @Override
    public Class<AuthorizationMatrixNodeProperty> getTarget() {
        return AuthorizationMatrixNodeProperty.class;
    }

    @Override
    protected AuthorizationMatrixNodeProperty instance(Mapping mapping, ConfigurationContext context) {
        return new AuthorizationMatrixNodeProperty();
    }

    @Override
    @NonNull
    public Set<Attribute<AuthorizationMatrixNodeProperty, ?>> describe() {
        return new HashSet<>(Arrays.asList(
                new MultivaluedAttribute<AuthorizationMatrixNodeProperty, String>("permissions", String.class)
                        .getter(unused -> null)
                        .setter(MatrixAuthorizationStrategyConfigurator::setLegacyPermissions),
                new MultivaluedAttribute<AuthorizationMatrixNodeProperty, DefinitionEntry>(
                                "entries", DefinitionEntry.class)
                        .getter(MatrixAuthorizationStrategyConfigurator::getEntries)
                        .setter(MatrixAuthorizationStrategyConfigurator::setEntries),
                new DescribableAttribute<AuthorizationMatrixNodeProperty, InheritanceStrategy>(
                        "inheritanceStrategy", InheritanceStrategy.class)));
    }
}
