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

import com.h3xstream.findsecbugs.common.StackUtils;
import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.OpcodeStack;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;
import org.apache.bcel.Constants;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class OneLoginSignAlgDetector extends OpcodeStackDetector {

    private static final String SAML_UNSAFE_SIGN = "SAML_UNSAFE_SIGN";
    private static final String XML_CONST1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String XML_CONST2 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    private static InvokeMatcherBuilder SIGN_ALG_CONSTRUCTOR = invokeInstruction().
            atClass("com.onelogin.saml2.settings.Saml2Settings").atMethod("setSignatureAlgorithm");

    private BugReporter bugReporter;

    public OneLoginSignAlgDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {

        if (seen == Const.INVOKEVIRTUAL && SIGN_ALG_CONSTRUCTOR.matches(this)) {
            final OpcodeStack.Item item = stack.getStackItem(0);


            if (item.getConstant().equals(XML_CONST1) || item.getConstant().equals(XML_CONST2)) {
                bugReporter.reportBug(new BugInstance(this, SAML_UNSAFE_SIGN, Priorities.NORMAL_PRIORITY) //
                        .addClass(this).addMethod(this).addSourceLine(this));
            }
        }
    }
}
