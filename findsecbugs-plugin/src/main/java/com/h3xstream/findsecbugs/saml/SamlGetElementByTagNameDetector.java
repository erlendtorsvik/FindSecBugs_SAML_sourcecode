/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

package com.h3xstream.findsecbugs.saml;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class SamlGetElementByTagNameDetector extends OpcodeStackDetector {
    private static final String SAML_GET_ELEMENT = "SAML_GET_ELEMENT";
    private static InvokeMatcherBuilder SAML_GET_ELEMENT_CONSTRUCTOR = invokeInstruction().atClass(
            "org/w3c/dom/Document").atMethod("getElementsByTagName");

    private BugReporter bugReporter;

    public SamlGetElementByTagNameDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {

        if (seen == Const.INVOKEINTERFACE && SAML_GET_ELEMENT_CONSTRUCTOR.matches(this)) {
            bugReporter.reportBug(new BugInstance(this, SAML_GET_ELEMENT, Priorities.HIGH_PRIORITY) //
                    .addClass(this).addMethod(this).addSourceLine(this));
        }
    }
}
