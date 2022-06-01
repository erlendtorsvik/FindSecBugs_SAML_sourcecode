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

public class SamlFeatureProcessingDetector extends OpcodeStackDetector {

    private static final String FEATURE_PROCESSING = "FEATURE_PROCESSING";
    private static final String XML_CONST = "http://javax.xml.XMLConstants/feature/secure-processing";
    private static InvokeMatcherBuilder FEAT_PROC_CONSTRUCTOR = invokeInstruction().
            atClass("javax.xml.parsers.DocumentBuilderFactory").atMethod("setFeature");

    private BugReporter bugReporter;

    public SamlFeatureProcessingDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {

        if (seen == Const.INVOKEVIRTUAL && FEAT_PROC_CONSTRUCTOR.matches(this)) {
            final OpcodeStack.Item item = stack.getStackItem(0);
            final OpcodeStack.Item item2 = stack.getStackItem(1);

            if (StackUtils.isConstantInteger(item) && (Integer) item.getConstant()  == 0 && item2.getConstant().equals(XML_CONST))
            {
                bugReporter.reportBug(new BugInstance(this, FEATURE_PROCESSING, Priorities.NORMAL_PRIORITY) //
                        .addClass(this).addMethod(this).addSourceLine(this));
            }
        }
    }

}
